## Part 1: Question 4 Setup

To run the programs on two different devices, connect the devices using an **Ethernet cable**. Follow these steps to ensure they are correctly connected:

### 1. Configure Network Settings  
1. Open **Control Panel** > **Network and Internet** > **Network and Sharing Center**.  
2. Click **Change adapter settings**.  
3. Identify the Ethernet connection associated with the cable.  
4. Right-click on it and select **Properties**.  
5. Check the box for **Internet Protocol Version 4 (TCP/IPv4)** and click **Properties**.  
6. Select **Use the following IP address** and set the following values:  

   - **Device 1:**  
     - **IP Address:** `192.168.1.1`  
     - **Subnet Mask:** `255.255.255.0`  

   - **Device 2:**  
     - **IP Address:** `192.168.1.2`  
     - **Subnet Mask:** `255.255.255.0`  

7. Click **OK** and close all windows.

### 2. Verify the Connection  
1. Open **Command Prompt (cmd)** or **Terminal**.  
2. Run the following command from one device:  

   ```sh
   ping 192.168.1.1  # Run from Device 2
