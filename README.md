# dnactemplate.py

## Introduction
This module is a very simple application that will query DNA Center and return the running configuration of all items in the database.   It will attempt to retrieve the hostname in the configuration and then use that hostname as a filename.   If the hostname wasn't found, it will attempt to search for the serial number.   If either was not found, then the file name will be the uuid of the device.

## Requirements
This module was written in Python 3.x