# WRM Tools Setup Guide

> **2 versions of defender and S.M.A.R.T. are there (because of not being a member of domain) so:**  
> - No MAC addresses for you :)  
> - We use IPv4 address and hostname this time because we are not stupid.

The reason is that they are in the cloud and they are not included in the DHCP server address leases, **so we fuck off**.

> **Additional setup for workgroup Windows Server members is needed.**

---

## 🖕 To Fuck Off, Do the Following:

Go to the Windows Server which is **not a domain member** but a **workgroup**.

### 🖥️ Remote PC Setup

1. **Open PowerShell on the remote machine (e.g., Windows Server) and execute:**

    ```powershell
    Enable-PSRemoting -Force
    ```

    > This is fucking important — **don't fuck it up**

2. **Enable Windows Remote Management in the firewall:**

    - Open **Windows Defender Firewall with Advanced Security**
    - Go to **Inbound Rules**
    - Locate `Windows Remote Management (HTTP-In)`  
      > *Note: There could be two or more. Each needs to be modified*
    - For each rule:
        - Right-click > **Properties**
        - Go to **Scopes**:
            - Set **Local IP address** and **Remote IP address** to `"Any IP Address"`
        - Go to **Advanced**:
            - Under **Profiles**, check all:
                - Domain
                - Private
                - Public

3. **Enable Windows Management Instrumentation in the firewall:**

    - Open **Windows Defender Firewall with Advanced Security**
    - Go to **Inbound Rules**
    - Locate the following:
        - `Windows Management Instrumentation (ASync-In)`
        - `Windows Management Instrumentation (DCOM-In)`
        - `Windows Management Instrumentation (WMI-In)`
    - For each rule:
        - Right-click > **Properties**
        - Go to **Scopes**:
            - Set **Local IP address** and **Remote IP address** to `"Any IP Address"`
        - Go to **Advanced**:
            - Under **Profiles**, check all:
                - Domain
                - Private
                - Public

---

### 💻 Client PC Setup

1. **On the client PC (your local machine), open PowerShell as Admin and execute:**

    ```powershell
    Enable-WSManCredSSP -Role Client -DelegateComputer <WORKGROUP MEMBER HOSTNAME> -Force
    ```

    > This is fucking important — **don't fuck it up**

    ```powershell
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "<WHAT EVER THE FUCK IS YOUR IPV4 HERE>" -Force
    ```

    > This is also fucking important — **don't fuck it up**

---

## 🎉 And Well Fucking Done, Mate!

---

### 🚧 Coming Soon

A detailed documentation because apparently, we don't make shit done —  
**because we are one lazy motherfuckers.**
