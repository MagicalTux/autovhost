// Set of defines for buffers management

#define BUF_STEP (256*1024)
#define BUF_MAX_WASTE (BUF_STEP*16)
#define BUF_MAX_SIZE (BUF_STEP*1024)

#define BUF_DEFINE(_name) char *_name = NULL; size_t _name ## _pos = 0; size_t _name ## _size = 0;

#define BUF_APPEND(_name, _var, _len) do { \
	if (_name ## _size <= (_name ## _pos + _len)) { \
		while (_name ## _size <= (_name ## _pos + _len)) \
			_name ## _size += (BUF_STEP); \
		if (_name ## _size > BUF_MAX_SIZE) abort(); \
		if (_name == NULL) \
			_name = malloc(_name ## _size); \
		else \
			_name = realloc(_name, _name ## _size); \
	} \
	memcpy(_name + _name ## _pos, _var, _len); \
	_name ## _pos += _len; \
} while(0)

#define BUF_EMPTY(_name) (_name ## _pos == 0)

#define BUF_WRITE(_fd, _name) do { \
	if (_name == NULL) break; \
	ssize_t res = write(_fd, _name, _name ## _pos); \
	if ((res == -1) && (errno != EAGAIN)) { \
		msg_log(LOG_WARNING, "Failed to write to socket: %s", strerror(errno)); \
		close(_fd); \
		_fd = 0; \
		_fd ## _status = 0; \
	} else if (_name ## _pos == res) { \
		_name ## _pos = 0; \
	} else { \
		memmove(_name, _name + res, _name ## _pos - res); \
		_name ## _pos -= res; \
	} \
	if ((_name ## _size - _name ## _pos) > BUF_MAX_WASTE) { \
		_name ## _size = ((size_t)((_name ## _pos) / BUF_STEP)) * BUF_STEP + BUF_STEP; \
		_name = realloc(_name, _name ## _size); \
	} \
} while(0)

