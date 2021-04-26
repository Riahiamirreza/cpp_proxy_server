#!/bin/bash

g++ -Wall -std=c++11 main.cpp -o main.out -lboost_system -lboost_thread -lpthread -lboost_log -DBOOST_LOG_DYN_LINK

