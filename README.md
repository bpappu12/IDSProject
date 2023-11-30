# IDSProject
1. Run the duckland.py python script - this will start to track all data on the network.
2. To test send packets do "sudo hping3 -S -p [Port #] [IP Address] - this sends good packets to test
3. Run the fakeintrusion.py script to send a faulty packet and stop the program
4. To see the detection log do "vim intrusiondetection.log" and it will bring up faulty logs
