# Pi Node Information
 
Công cụ pini dùng để chuẩn đoán và phân tích các thông tin liên quan đến docker, container, stellar của ứng dụng Pi node trên hệ điều hành Windows 10 Pro.

pini is tiny tool to diagnose and analyze the running of docker, container and stellar in Windows 10 Pro

## Overview - Tổng quan

Kiểm tra thông tin chi tiết của hệ điều hành Windows hiện tại

_Check detail status of current Windows OS_

Kiểm tra trạng thái của 3-10 cổng mặc định của ứng dụng Pi node

_Check 3-10 major port numbers of Pi node_

Kiểm tra thông tin chi tiết của docker, Pi node, vpnkit, vmmem, wsl

_Check detail status of docker, Pi, vpnkit, vmmem, wsl_

Kiểm tra và phân tích thông tin chi tiết của pi-consensus, testnet2

_Diagnose and analyze the status of pi-consensus_

Lưu lại kết quả để tham khảo

_Save to file for reference_

## Usage - Cách dùng
Tải ứng dụng về máy, cụ thể lưu ở ổ đĩa C:, sau đó bấm chuột phải chọn" Run with Powershell".

_Download pini.ps1 tool then save to C: drive. Right click then choose "Run with Powershell"_

Lưu ý: Cần cho phép ứng dụng được phép chạy trong Powershell

_Note: Run as Administrator in Powershell if any._

Execution Policy Change

Set-ExecutionPolicy unrestricted

The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
http://go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): **Y**


## Screenshot - Hình chụp
[![pini](https://github.com/pkk68/pini/blob/main/2024-10-21%2022_01_42-Administrator_%20Windows%20PowerShell.png)]
