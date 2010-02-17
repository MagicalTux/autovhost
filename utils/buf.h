// Set of defines for buffers management

#define BUF_STEP 256*1024

#define BUF_DEFINE(_name) char *_name = NULL; size_t _name ## _pos = 0; size_t _name ## _size = 0;

#define BUF_APPEND(_name, _var, _len) do { \
	if ((_name ## _pos + _name ## _size) <= _len) { \
		while ((_name ## _pos + _name ## _size) <= _len) \
			_name ## _size += (BUF_STEP); \
		if (_name == NULL) \
			_name = malloc(_name ## _size); \
		else \
		_name = realloc(_name, _name ## _size); \
	} \
	memcpy(_name + _name ## _pos, _var, _len); \
	_name ## _pos += _len; \
} while(0)

