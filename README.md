# UltimateWDACByPassList
A centralized resource for previously documented WDAC bypass techniques. 

*Many of the LOLBINs are included on the [Microsoft Recommended Block Rules List](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules)

------------------------------
###Block Rules "LOLBIN" Write-Ups


####addinprocess.exe
 - James Forshaw (@tiraniddo)
 - DG on Windows 10 S: Executing Arbitrary Code
  - https://www.tiraniddo.dev/2017/07/dg-on-windows-10-s-executing-arbitrary.html

####addinprocess32.exe
 - James Forshaw (@tiraniddo)
 - DG on Windows 10 S: Executing Arbitrary Code 
   - https://www.tiraniddo.dev/2017/07/dg-on-windows-10-s-executing-arbitrary.html

####aspnet_compiler.exe
 - cpl (@cpl3h)
 - The Curious Case of Aspnet_Compiler.exe
   - https://ijustwannared.team/2020/08/01/the-curious-case-of-aspnet_compiler-exe/

####bginfo.exe
 - Oddvar Moe (@Oddvarmoe)
 - Bypassing Application Whitelisting with BGInfo
  - https://msitpros.com/?p=3831

####cdb.exe
- Matt Graeber (@mattifestation)
- Bypassing Application Whitelisting by using WinDbg/CDB as a Shellcode Runner
  - http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html

####csi.exe
 - Casey Smith (@subTee)
 - Application Whitelisting Bypass - CSI.EXE C# Scripting
  - https://web.archive.org/web/20161008143428/http://subt0x10.blogspot.com/2016/09/application-whitelisting-bypass-csiexe.html

####dbghost.exe
- Matt Graeber (@mattifestation)
- dbghost.exe - Ghost And The Darkness
  - https://web.archive.org/web/20170926164017/http://subt0x10.blogspot.com/2017/09/dbghostexe-ghost-in-darkness.html

####dnx.exe
- Matt Nelson (@enigma0x3)
- BYPASSING APPLICATION WHITELISTING BY USING DNX.EXE
  - https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/

####dotnet.exe
 - Jimmy Bayne (@bohops)
 - DotNet Core: A Vector For AWL Bypass & Defense Evasion
   - https://bohops.com/2019/08/19/dotnet-core-a-vector-for-awl-bypass-defense-evasion/

####fsi.exe
 - Nick Tyrer (@NickTyrer)
 - GitHub Gist: fsi.exe inline execution
   - https://gist.github.com/NickTyrer/51eb8c774a909634fa69b4d06fc79ae1
   - https://twitter.com/NickTyrer/status/904273264385589248

####fsiAnyCpu.exe
 - Nick Tyrer (@NickTyrer) via fsi.exe inline execution
 - GitHub Gist: fsi.exe inline execution
   - https://gist.github.com/NickTyrer/51eb8c774a909634fa69b4d06fc79ae1
   - https://twitter.com/bohops/status/1319096336441090050

####infdefaultinstall.exe
 - Kyle Hanslovan (@KyleHanslovan), Chris Bisnett (@chrisbisnett)
   - https://github.com/huntresslabs/evading-autoruns
 - RE: Evading Autoruns PoCs on Windows 10
   - https://medium.com/@KyleHanslovan/re-evading-autoruns-pocs-on-windows-10-dd810d7e8a3f

####microsoft.Workflow.Compiler.exe
 - Matt Graeber (@mattifestation)
 - Arbitrary, Unsigned Code Execution Vector in Microsoft.Workflow.Compiler.exe
   - https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb

####msbuild.exe
 - Casey Smith (@subTee)
 - Bypassing Application Whitelisting using MSBuild.exe - Device Guard Example and Mitigations
   - https://web.archive.org/web/20160920161634/http://subt0x10.blogspot.com/2016/09/bypassing-application-whitelisting.html

####mshta.exe
 - Unknown (Documented by @conscioushacker)
 -  Application Whitelisting Bypass: mshta.exe
  - https://web.archive.org/web/20171118145940/http://blog.conscioushacker.io/index.php/2017/11/17/application-whitelisting-bypass-mshta-exe/

####powershellcustomhost.exe
 - Lasse Trolle Borup (@TrolleBorup)
 - A simple Device Guard bypass
  - https://danishcyberdefence.dk/blog/device-guard-powershellcustomhost

####rcsi.exe
 - Matt Nelson (@enigma0x3)
 - BYPASSING APPLICATION WHITELISTING BY USING RCSI.EXE
  - https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/

####runscripthelper.exe
 - Matt Graeber (@mattifestation)
 - Bypassing Application Whitelisting with runscripthelper.exe
  - https://posts.specterops.io/bypassing-application-whitelisting-with-runscripthelper-exe-1906923658fc

####visualuiaverifynative.exe
 - Lee Christensen (@tifkin_) [Write-up: Jimmy Bayne (@bohops)]
 - Exploring the WDAC Microsoft Recommended Block Rules: VisualUiaVerifyNative
  - https://bohops.com/2020/10/15/exploring-the-wdac-microsoft-recommended-block-rules-visualuiaverifynative/

####windbg.exe
 - Matt Graeber (@mattifestation)
 - Bypassing Application Whitelisting by using WinDbg/CDB as a Shellcode Runner
   - http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html

####wmic.exe
 - Casey Smith (@subTee)
 - WMIC.EXE Whitelisting Bypass - Hacking with Style, Stylesheets
  - https://web.archive.org/web/20190814201250/https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html


------------------------------
Other "Unsigned Code Execution" LOLBINs (not on list)

####dbgsrv.exe
 - Casey Smith (@subTee) , Ross Wolf (@rw_access)
 - How to Bypass WDAC with dbgsrv.exe
  - https://fortynorthsecurity.com/blog/how-to-bypass-wdac-with-dbgsrv-exe/
 - Fantastic Red-Team Attacks and How to Find Them
  - https://i.blackhat.com/USA-19/Thursday/us-19-Smith-Fantastic-Red-Team-Attacks-And-How-To-Find-Them.pdf

------------------------------
###COM/Microsoft Office/Active Scripting Languages (jscript.dll, msxml3.dll, msxml6.dll)

- Sneaking Past Device Guard
  - Philip Tsukerman (@PhilipTsukerman)
  - https://conference.hitb.org/hitbsecconf2019ams/materials/D2T1%20-%20Sneaking%20Past%20Device%20Guard%20-%20Philip%20Tsukerman.pdf

- WSH INJECTION: A CASE STUDY
  - Matt Nelson (@enigma0x3)
  - https://enigma0x3.net/2017/08/03/wsh-injection-a-case-study/
  
- Application Whitelisting Bypass and Arbitrary Unsigned Code Execution Technique in winrm.vbs
  - Matt Graeber (@mattifestation)
  - https://posts.specterops.io/application-whitelisting-bypass-and-arbitrary-unsigned-code-execution-technique-in-winrm-vbs-c8c24fb40404
  
- COM XSL Transformation: Bypassing Microsoft Application Control Solutions (CVE-2018-8492) 
  - Jimmy Bayne (@bohops) 
  - https://bohops.com/2019/01/10/com-xsl-transformation-bypassing-microsoft-application-control-solutions-cve-2018-8492/

- Abusing Catalog Hygiene to Bypass Application Whitelisting
  - Jimmy Bayne (@bohops)
  - https://bohops.com/2019/05/04/abusing-catalog-file-hygiene-to-bypass-application-whitelisting/

- BYPASSING DEVICE GUARD UMCI USING CHM – CVE-2017-8625 
  - Oddvar Moe (@Oddvarmoe), Matt Nelson (@enigma0x3)
  - https://oddvar.moe/2017/08/13/bypassing-device-guard-umci-using-chm-cve-2017-8625/

 
------------------------------
###Novel Living-of-the-land Abuse

 - cc: @mattifestation, @enigma0x3, @tiraniddo, @hexacorn
 - To do...


------------------------------
###PowerShell

 - cc: @mattifestation, @enigma0x3, @tiraniddo
 - To do...


------------------------------
###On Block List - Not Documented Yet...

addinutil.exe
bash.exe
dbgsvc.exe
kd.exe
kill.exe
lxrun.exe
ntkd.exe
ntsd.exe
texttransform.exe
wfc.exe
wsl.exe
wslconfig.exe
wslhost.exe

------------------------------
###Libraries On List (Independent usage may/may not be interesting)


Microsoft.Build.dll
Microsoft.Build.Framework.dll
msbuild.dll
lxssmanager.dll
system.management.automation.dll
