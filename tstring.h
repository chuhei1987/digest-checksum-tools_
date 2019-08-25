
/*
 text utilities - Some written in C++ for Windows platform.
 https://github.com/fshb/textutil/
 Copyright (c) 2019 Sun Hongbo (Felix)

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this Software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
*/
#pragma once


#include <stdarg.h>
#include <stdio.h>
#include <tchar.h>
#include <vector>
#include <string>
#include <algorithm>

class TString : public std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR> >
{
private:
	typedef std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR> > _Base;

public:
	typedef std::vector<TString> TStringList;

public:
	//constructors
	TString() : _Base() {}
	TString(const TString& s) : _Base((_Base)s) {}
	TString(const _Base& s) : _Base(s) {}

	TString(const TString& s, size_type pos, size_type len = npos) : _Base((_Base)s, pos, len) {}
	TString(const _Base& s, size_type pos, size_type len = npos) : _Base(s, pos, len) {}

	TString(const TCHAR* s) : _Base(s) {}
	TString(const TCHAR* s, size_type n) : _Base(s, n) {}

	TString(size_type n, TCHAR c) : _Base(n, c) {}

	template <class IteratorT>
	TString(IteratorT first, IteratorT last) : _Base(first, last) {}

public:
	template<class StrT> TString operator + (StrT& s)
	{
		_Base ss = (_Base)* this;
		ss += s;

		TString ts(ss);
		return ts;
	}

	void operator = (const TString& s)
	{
		_Base* this_base = (_Base*)this;
		*this_base = (_Base)s;
	}

	void operator = (const _Base& s)
	{
		_Base* this_base = (_Base*)this;
		*this_base = s;
	}

	void operator = (const TCHAR* s)
	{
		_Base* this_base = (_Base*)this;
		*this_base = s;
	}

	void operator += (const TString& s)
	{
		_Base* this_base = (_Base*)this;
		*this_base += (_Base)s;
	}

	void operator += (const _Base& s)
	{
		_Base* this_base = (_Base*)this;
		*this_base += s;
	}
	void operator += (const TCHAR* s)
	{
		_Base* this_base = (_Base*)this;
		*this_base += s;
	}


	template<class StrT> TString& operator << (StrT& s)
	{
		*this += s;
		return *this;
	}

	template<class StrT> bool operator == (const StrT& s) const
	{
		_Base* this_base = (_Base*)this;
		return (*this_base == s);
	}

	template<class StrT> bool operator != (StrT& s)
	{
		_Base* this_base = (_Base*)this;
		return (*this_base != s);
	}

	TString substr(size_type pos = 0, size_type len = npos) const
	{
		TString s(_Base::substr(pos, len));
		return s;
	}

	TString& to_lower()
	{
		std::transform(begin(), end(), begin(), tolower);
		return *this;
	}
	TString& to_upper()
	{
		std::transform(begin(), end(), begin(), toupper);
		return *this;
	}

	TString& vformat(const TCHAR* fmt, va_list ap)
	{
		unsigned int sz = 1 + _vsctprintf(fmt, ap);
		TCHAR* buf = new TCHAR[sz];
		_vstprintf_s(buf, sz, fmt, ap);
		*this = buf;
		delete[] buf;

		return *this;
	}

	TString& format(const TCHAR* fmt, ...)
	{
		va_list ap;
		va_start(ap, fmt);
		vformat(fmt, ap);
		va_end(ap);

		return *this;
	}
	TStringList split(const TString& delimiter) const
	{
		TStringList slist;
		size_type len = delimiter.length();
		size_type pos1 = 0;
		size_type pos2 = find(delimiter);
		while (pos2 != npos)
		{
			slist.push_back(substr(pos1, pos2 - pos1));
			pos1 = pos2 + len;
			pos2 = find(delimiter, pos1);
		}
		slist.push_back(substr(pos1));
		return slist;
	}

	bool is_null()
	{
		return (*this == _T(""));
	}

	size_type find(const TString& s, const size_t pos = 0) const
	{
		return _Base::find((_Base)s, pos);
	}

	size_type rfind(const TString& s, const size_t pos = 0) const
	{
		return _Base::rfind((_Base)s, pos);
	}

	TString& replace_with(const TString& from, const TString& to)
	{
		size_type pos = 0;
		while (true)
		{
			pos = find(from, pos);
			if (pos != npos)
			{
				_Base::replace(pos, from.length(), (_Base)to);
				pos = 0;
			}
			else
				break;
		}
		return *this;
	}
};

typedef TString::TStringList str_list;
typedef TString::TStringList strs;
typedef TString str;

class TMessageHandler
{
private:
	struct message_t
	{
		int priority;
		bool suppress;
		str message;
		message_t() : priority(0), suppress(false) {}
	};
	std::vector<message_t> _msgs;

	FILE* _out_stream;

	str _delimiter;

public:
	TMessageHandler() : _out_stream(stdout), _delimiter(_T("\n")) {}
	TMessageHandler(FILE* f) : _out_stream(f), _delimiter(_T("\n")) {}

	~TMessageHandler()
	{
		_msgs.clear();
	}

	void set_outstream(FILE* outstream)
	{
		_out_stream = outstream;
	}
	TMessageHandler& operator()(int priority = 0, bool suppress = false)
	{
		message_t message;
		message.priority = priority;
		message.suppress = suppress;
		_msgs.push_back(message);
		return *this;
	}

	template<class T> TMessageHandler& operator << (T& message)
	{
		size_t i = _msgs.size() - 1;
		_msgs[i].message << message;
		return *this;
	}

	size_t count()
	{
		return _msgs.size();
	}

	bool is_empty()
	{
		return (count() == 0);
	}

	TMessageHandler& set_delimiter(str delim)
	{
		_delimiter = delim;
		return *this;
	}

	TMessageHandler& vformat(const TCHAR* fmt, va_list ap)
	{
		size_t i = _msgs.size() - 1;
		_msgs[i].message.vformat(fmt, ap);
		return *this;
	}

	TMessageHandler& format(const TCHAR* fmt, ...)
	{
		va_list ap;
		va_start(ap, fmt);
		vformat(fmt, ap);
		va_end(ap);
		return *this;
	}

	void print()
	{
		struct
		{
			bool operator()(message_t& msg1, message_t& msg2)
			{
				return (msg1.priority < msg2.priority);
			}
		} _ascending_order;

		std::sort(_msgs.begin(), _msgs.end(), _ascending_order);

		struct PRINT_T
		{
		private:
			FILE* _out_stream;
			str _delimiter;
		public:
			PRINT_T(FILE* f, str delim) : _out_stream(f), _delimiter(delim) {}
			void operator()(message_t& message)
			{
				if (!message.suppress)
					_ftprintf(_out_stream, _T("%s%s"), message.message.c_str(), _delimiter.c_str());
			}
		} _print_msg(_out_stream, _delimiter);

		std::for_each(_msgs.begin(), _msgs.end(), _print_msg);
	}
};

typedef TMessageHandler msg_handler;

