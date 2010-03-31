// Set of defines for buffers management

#define BUF_STEP 256*1024

#define BUF_DEFINE(_name) char *_name = NULL; size_t _name ## _pos = 0; size_t _name ## _size = 0;

#define BUF_APPEND(_name, _var, _len) do { \
	if (_name ## _size <= (_name ## _pos + _len)) { \
		while (_name ## _size <= (_name ## _pos + _len)) \
			_name ## _size += (BUF_STEP); \
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
	size_t res = write(_fd, _name, _name ## _pos); \
	if (res == -1) { \
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
} while(0)

