#!/usr/bin/python -O

import sys
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
	return "URL: /\n"

@app.route('/test1')
def test1():
	return "URL: /test1\n"

@app.route('/test2')
def test2():
	return "URL: /test2\n"

###

@app.route('/product')
def product():
	return "URL: /product\n"

@app.route('/product/item1')
def product_item1():
	return "URL: /product/item1\n"

@app.route('/product/item1/status')
def product_item1_status():
	return "URL: /product/item1/status\n"

###

@app.route('/product/item2')
def product_item2():
	return "URL: /product/item2\n"

@app.route('/product/item2/status')
def product_item2_status():
	return "URL: /product/item2/status\n"

###

@app.route('/product/item3')
def product_item3():
	return "URL: /product/item3\n"

@app.route('/product/item3/status')
def product_item3_status():
	return "URL: /product/item3/status\n"

###	

@app.route('/product/item4')
def product_item4():
	return "URL: /product/item4\n"

@app.route('/product/item4/status')
def product_item4_status():
	return "URL: /product/item4/status\n"

###

@app.route('/product/item5')
def product_item5():
	return "URL: /product/item5\n"

@app.route('/product/item5/status')
def product_item5_status():
	return "URL: /product/item5/status\n"

###

if len(sys.argv) != 2:
	print("Usage: {} [port]".format(sys.argv[0]))

app.run(host='0.0.0.0', port=int(sys.argv[1]), threaded=True)
