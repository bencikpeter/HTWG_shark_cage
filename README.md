# Shark Cage Team project
This project contains windows programs to isolate a program in an own desktop to prevent malware (without OS privileges) to capture user input or sreenshots.
It consists of 5 sub-programs: The Cage Service, Cage Manager, StarterCMD, ImageSelectDialog and a project for testing. The 3 actual parts (Service, Manager and StarterCMD) communicate over a TCP connection to interchange messages.

## Components

### Cage Service
The Cage Service implements a Windows service running the background. It receives messages from the UI and sends messages to the Cage Manager.

### Cage Manager
The Cage Manager creates a new desktop and processes in it, according to the messages received by the Cage Service.

### StarterCMD
A user interface for starting the Cage Manager and an application in it. Directly communicating with the Cage Service.

### ImageSelectDialog
A user interface to select an icon to be displayed on the user's desktop. config.txt will be created in C:\sharkcage with a line containing "picture: " followed by the index of the icon. The Cage Service reads this configuration file and searches for a line containing "picture:" and opens the dialog if the file contains no such line.

### Shark Cage
Dummy project used for testing conponents. Contains no actual functionality.

## Installation
1. Build the project
2. Create the folder C:\sharkcage and copy "Cage service.exe" and CageManager.exe to this folder.
3. Also copy ImageSelectDialog.exe to this directory.
4. Open a CMD a administrator and add "Cage service.exe" to the services: ```sc create "Cage Service" binPath= "C:\sharkcage\Cage service.exe" obj= "NT AUTHORITY\SYSTEM"```

## Useful Links
Our [Jenkins Server](http://35.162.112.109:8080/)
