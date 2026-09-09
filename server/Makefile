# sakichat_server —— C++ epoll + WebSocket 聊天服务器
# 依赖：apt install libsqlite3-dev libssl-dev

CC      = g++
CFLAGS  = -std=c++17 -Wall -O2
LDFLAGS = -lssl -lcrypto -lsqlite3 -lsqlite3                                                                                        

all: sakichat_server

sakichat_server: main.cpp websocket.h
	$(CC) $(CFLAGS) main.cpp -o sakichat_server $(LDFLAGS)

clean:
	rm -f sakichat_server

.PHONY: all clean
