# Crypto API

Code for my final university project/thesis titled "Digital Certification in IoT Devices."

## Goal

This project aims to provide a quick way to benchmark between the most popular and high-rated cryptography libraries available to ESP32. The main focus is in digital signatures and certifications.

## Requirements

- ESP-IDF: This project uses the ESP-IDF framework, so you'll need ESP-IDF installed and configured on your machine.
- WolfSSL: This project uses wolfssl, but in it's source code needs to be outside of it. Follow the instructions below on how to do it.

## Setting up WolfSSL

1) Download the WolfSSL source code from it's GitHub page (v5.7.4-stable);
2) Unzip the downloaded zip file, and move it to your desired location (ex: ```C:/wolfssl-source```);
3) Create a system-wide environment variable called ```WOLFSSL_ROOT```, pointing to the location of the wolfssl source code (ex: ```C:/wolfssl-source```);
4) Restart your machine;
5) After these steps, when compiling the project, it should be able to automatically detect the wolfssl folder and use it to generate the builder folder.

## Choosing which library and algorithm to use

In the main.cpp file, there's a call to a function named "perform_tests". This function is used for testing purposes, and it's parameters enable you to choose which library, signature algorithm and hash algorithm to use. Change them as you like.

## Running the project

First of all, make sure your esp32 device is connected to your mahcine. Then open the ```ESP-IDF PowerShell``` or ```ESP-IDF CMD``` that was installed when you installed ESP-IDF, and navigate to project root folder (ex: ```cd <path-to-project>/esp32-crypto-api```).

The project already has a build folder, so you can try simply running the project with ```idf.py flash``` and then ```idf.py monitor``` to flash the project to your device and start monitoring it. However, if this fails for some reason, delete the build folder, and execute the following commands:

1) ```idf.py set-target esp32```
2) ```idf.py build``` (alternatively, if using VSCode, ```CTRL + SHIFT + P``` and select ```ESP-IDF: Build your project```
3) ```idf.py flash``` (alternatively, if using VSCode, ```CTRL + SHIFT + P``` and select ```ESP-IDF: Flash your project```
4) ```idf.py monitor``` (alternatively, if using VSCode, ```CTRL + SHIFT + P``` and select ```ESP-IDF: Monitor device```

After this, the project should be up and running on your device.
