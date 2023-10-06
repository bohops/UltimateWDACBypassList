# Ultimate WDAC Bypass List

A centralized resource for previously documented WDAC/Device Guard/UMCI bypass techniques as well for building/managing/testing WDAC policies

*Many of the LOLBINs are included on the [Applications that can bypass WDAC List](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac) formerly called the "Microsoft Recommended Block Rules List"

*This repository was inspired by [Oddvar Moe](https://twitter.com/Oddvarmoe)'s [Ultimate AppLocker Bypass List](https://github.com/api0cradle/UltimateAppLockerByPassList)

*As always, this is a work in progress...

------------------------------
### Microsoft Recommended Block Rules - "LOLBIN" Write-Ups

#### addinprocess.exe
 - By James Forshaw (@tiraniddo)
 - DG on Windows 10 S: Executing Arbitrary Code
   - https://www.tiraniddo.dev/2017/07/dg-on-windows-10-s-executing-arbitrary.html

#### addinprocess32.exe
 - By James Forshaw (@tiraniddo)
 - DG on Windows 10 S: Executing Arbitrary Code 
   - https://www.tiraniddo.dev/2017/07/dg-on-windows-10-s-executing-arbitrary.html

#### addinutil.exe
 - By Unknown (Documented by @McKinleyMike and @TheLatteri)
 - Insecure Deserialization in AddinUtil.exe 
   - https://www.blue-prints.blog/content/blog/posts/lolbin/addinutil-lolbas.html

#### aspnet_compiler.exe
 - By cpl (@cpl3h)
 - The Curious Case of Aspnet_Compiler.exe
   - https://ijustwannared.team/2020/08/01/the-curious-case-of-aspnet_compiler-exe/

#### bginfo.exe
 - By Oddvar Moe (@Oddvarmoe)
 - Bypassing Application Whitelisting with BGInfo
   - https://msitpros.com/?p=3831

#### cdb.exe
- By Matt Graeber (@mattifestation)
- Bypassing Application Whitelisting by using WinDbg/CDB as a Shellcode Runner
  - http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html

#### csi.exe
 - By Casey Smith (@subTee)
 - Application Whitelisting Bypass - CSI.EXE C# Scripting
   - https://web.archive.org/web/20161008143428/http://subt0x10.blogspot.com/2016/09/application-whitelisting-bypass-csiexe.html

#### dbghost.exe
- By Casey Smith (@subTee)
- dbghost.exe - Ghost And The Darkness
  - https://web.archive.org/web/20170926164017/http://subt0x10.blogspot.com/2017/09/dbghostexe-ghost-in-darkness.html

#### dnx.exe
- By Matt Nelson (@enigma0x3)
- BYPASSING APPLICATION WHITELISTING BY USING DNX.EXE
  - https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/

#### dotnet.exe
 - By Jimmy Bayne (@bohops)
 - DotNet Core: A Vector For AWL Bypass & Defense Evasion
   - https://bohops.com/2019/08/19/dotnet-core-a-vector-for-awl-bypass-defense-evasion/

#### fsi.exe
 - By Nick Tyrer (@NickTyrer) [Write-up: Jimmy Bayne (@bohops)]
 - GitHub Gist: fsi.exe inline execution
   - https://gist.github.com/NickTyrer/51eb8c774a909634fa69b4d06fc79ae1
   - https://twitter.com/NickTyrer/status/904273264385589248
 - Exploring the WDAC Microsoft Recommended Block Rules (Part II): Wfc.exe, Fsi.exe, and FsiAnyCpu.exe
   - https://bohops.com/2020/11/02/exploring-the-wdac-microsoft-recommended-block-rules-part-ii-wfc-fsi/

#### fsiAnyCpu.exe
 - By Nick Tyrer (@NickTyrer) via fsi.exe inline execution [Write-up: Jimmy Bayne (@bohops)]
 - GitHub Gist: fsi.exe inline execution
   - https://gist.github.com/NickTyrer/51eb8c774a909634fa69b4d06fc79ae1
   - https://twitter.com/bohops/status/1319096336441090050
 - Exploring the WDAC Microsoft Recommended Block Rules (Part II): Wfc.exe, Fsi.exe, and FsiAnyCpu.exe
   - https://bohops.com/2020/11/02/exploring-the-wdac-microsoft-recommended-block-rules-part-ii-wfc-fsi/

#### infdefaultinstall.exe
 - By Kyle Hanslovan (@KyleHanslovan), Chris Bisnett (@chrisbisnett)
 - Evading Autoruns - DerbyCon 7.0
   - https://github.com/huntresslabs/evading-autoruns
 - RE: Evading Autoruns PoCs on Windows 10
   - https://medium.com/@KyleHanslovan/re-evading-autoruns-pocs-on-windows-10-dd810d7e8a3f

#### InstallUtil.exe
 - By James Forshaw (@tiraniddo)
 - DG on Windows 10 S: Abusing InstallUtil
   - https://www.tiraniddo.dev/2017/08/dg-on-windows-10-s-abusing-installutil.html


#### kill.exe
  - By @hyp3rlinx
  - Microsoft Process Kill Utility "kill.exe" - SEH Buffer Overflow
    - http://hyp3rlinx.altervista.org/advisories/MS-KILL-UTILITY-BUFFER-OVERFLOW.txt
    - https://twitter.com/bohops/status/1324563760967753730

#### microsoft.Workflow.Compiler.exe
 - By Matt Graeber (@mattifestation)
 - Arbitrary, Unsigned Code Execution Vector in Microsoft.Workflow.Compiler.exe
   - https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb

#### msbuild.exe
 - By Casey Smith (@subTee)
 - Bypassing Application Whitelisting using MSBuild.exe - Device Guard Example and Mitigations
   - https://web.archive.org/web/20160920161634/http://subt0x10.blogspot.com/2016/09/bypassing-application-whitelisting.html

#### mshta.exe
 - By Unknown (Documented by @conscioushacker)
 -  Application Whitelisting Bypass: mshta.exe
    - https://web.archive.org/web/20171118145940/http://blog.conscioushacker.io/index.php/2017/11/17/application-whitelisting-bypass-mshta-exe/

#### powershellcustomhost.exe
 - By Lasse Trolle Borup (@TrolleBorup)
 - A simple Device Guard bypass
   - https://danishcyberdefence.dk/blog/device-guard-powershellcustomhost

#### rcsi.exe
 - By Matt Nelson (@enigma0x3)
 - BYPASSING APPLICATION WHITELISTING BY USING RCSI.EXE
   - https://enigma0x3.net/2016/11/21/bypassing-application-whitelisting-by-using-rcsi-exe/

#### runscripthelper.exe
 - By Matt Graeber (@mattifestation)
 - Bypassing Application Whitelisting with runscripthelper.exe
   - https://posts.specterops.io/bypassing-application-whitelisting-with-runscripthelper-exe-1906923658fc

#### visualuiaverifynative.exe
 - By Lee Christensen (@tifkin_) [Write-up: Jimmy Bayne (@bohops)]
 - Exploring the WDAC Microsoft Recommended Block Rules: VisualUiaVerifyNative
   - https://bohops.com/2020/10/15/exploring-the-wdac-microsoft-recommended-block-rules-visualuiaverifynative/

#### wfc.exe
 - Tipped by MSRC and Matt Graeber (@mattifestation) [Write-up: Jimmy Bayne (@bohops)]
 - Exploring the WDAC Microsoft Recommended Block Rules (Part II): Wfc.exe, Fsi.exe, and FsiAnyCpu.exe
  - https://bohops.com/2020/11/02/exploring-the-wdac-microsoft-recommended-block-rules-part-ii-wfc-fsi/

#### windbg.exe
 - By Matt Graeber (@mattifestation)
 - Bypassing Application Whitelisting by using WinDbg/CDB as a Shellcode Runner
   - http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html

#### wmic.exe
 - By Casey Smith (@subTee)
 - WMIC.EXE Whitelisting Bypass - Hacking with Style, Stylesheets
   - https://web.archive.org/web/20190814201250/https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html

#### WSL Family - bash.exe, lxrun.exe, wsl.exe, wslconfig.exe, wslhost.exe
 - By Alex Ionescu (@aionescu)
 - Fun with the Windows Subsystem for Linux
   -  https://github.com/ionescu007/lxss

#### On Block List - Not Documented Yet...

- dbgsvc.exe
- IntuneWindowsAgent.exe
- kd.exe
- ntkd.exe
- ntsd.exe
- texttransform.exe
- HVCIScan.exe

#### Libraries On List (Independent usage may/may not be interesting)

- Microsoft.Build.dll
- Microsoft.Build.Framework.dll
- msbuild.dll
- lxssmanager.dll
- system.management.automation.dll
- davsvc.dll
- mfc40.dll

------------------------------
### Other "Unsigned Code Execution" LOLBINs (not on list)

#### dbgsrv.exe
 - By Casey Smith (@subTee) , Ross Wolf (@rw_access)
 - How to Bypass WDAC with dbgsrv.exe
   - https://fortynorthsecurity.com/blog/how-to-bypass-wdac-with-dbgsrv-exe/
 - Fantastic Red-Team Attacks and How to Find Them
   - https://i.blackhat.com/USA-19/Thursday/us-19-Smith-Fantastic-Red-Team-Attacks-And-How-To-Find-Them.pdf

------------------------------
### PowerShell

#### UMCI BYPASS USING PSWORKFLOWUTILITY: CVE-2017-0215
 - By Matt Nelson (@enigma0x3)
 - https://enigma0x3.net/2017/10/19/umci-bypass-using-psworkflowutility-cve-2017-0215/

#### DEFEATING DEVICE GUARD: A LOOK INTO CVE-2017-0007
 - By Matt Nelson (@enigma0x3)
 - https://enigma0x3.net/2017/04/03/defeating-device-guard-a-look-into-cve-2017-0007/

#### Exploiting PowerShell Code Injection Vulnerabilities to Bypass Constrained Language Mode
 - By Matt Graeber (@mattifestation)
 - http://www.exploit-monday.com/2017/08/exploiting-powershell-code-injection.html

#### A LOOK AT CVE-2017-8715: BYPASSING CVE-2017-0218 USING POWERSHELL MODULE MANIFESTS
 - By Matt Nelson (@enigma0x3)
 - https://enigma0x3.net/2017/11/06/a-look-at-cve-2017-8715-bypassing-cve-2017-0218-using-powershell-module-manifests/

#### CVE-2018-8212: DEVICE GUARD/CLM BYPASS USING MSFT_SCRIPTRESOURCE
 - By Matt Nelson (@enigma0x3)
 - https://enigma0x3.net/2018/10/10/cve-2018-8212-device-guard-clm-bypass-using-msft_scriptresource/
 
#### Invoke-History Constrained Language Mode Bypass 
 - By Matt Graeber (@mattifestation)
 - https://twitter.com/mattifestation/status/1095416185053696000
 
 
------------------------------
### Novel Living-Of-The-Land/COM/Microsoft Office/Active Scripting Languages (jscript.dll, msxml3.dll, msxml6.dll)

#### Bypassing Device Guard with .NET Assembly Compilation Methods
 - By Matt Graeber (@mattifestation)
 - http://www.exploit-monday.com/2017/07/bypassing-device-guard-with-dotnet-methods.html

#### Sneaking Past Device Guard (+ CVE-2018-8417)
 - By Philip Tsukerman (@PhilipTsukerman)
 - https://conference.hitb.org/hitbsecconf2019ams/materials/D2T1%20-%20Sneaking%20Past%20Device%20Guard%20-%20Philip%20Tsukerman.pdf

#### WLDP CLSID policy .NET COM Instantiation UMCI Bypass
 - By James Forshaw (@tiraniddo)
 - https://bugs.chromium.org/p/project-zero/issues/detail?id=1514&q=

#### WSH INJECTION: A CASE STUDY
 - By Matt Nelson (@enigma0x3)
 - https://enigma0x3.net/2017/08/03/wsh-injection-a-case-study/
  
#### Application Whitelisting Bypass and Arbitrary Unsigned Code Execution Technique in winrm.vbs
 - By Matt Graeber (@mattifestation)
 - https://posts.specterops.io/application-whitelisting-bypass-and-arbitrary-unsigned-code-execution-technique-in-winrm-vbs-c8c24fb40404
  
#### COM XSL Transformation: Bypassing Microsoft Application Control Solutions (CVE-2018-8492) 
 - By Jimmy Bayne (@bohops) 
 - https://bohops.com/2019/01/10/com-xsl-transformation-bypassing-microsoft-application-control-solutions-cve-2018-8492/

#### Abusing Catalog Hygiene to Bypass Application Whitelisting
 - By Jimmy Bayne (@bohops)
 - https://bohops.com/2019/05/04/abusing-catalog-file-hygiene-to-bypass-application-whitelisting/

#### BYPASSING DEVICE GUARD UMCI USING CHM – CVE-2017-8625 
 - By Oddvar Moe (@Oddvarmoe), Matt Nelson (@enigma0x3)
 - https://oddvar.moe/2017/08/13/bypassing-device-guard-umci-using-chm-cve-2017-8625/

#### UMCI VS INTERNET EXPLORER: EXPLORING CVE-2017-8625
 - By Matt Nelson (@enigma0x3)
 - https://enigma0x3.net/2017/08/24/umci-vs-internet-explorer-exploring-cve-2017-8625/
 
#### Bypassing WDAC with Previous Versions of Signed Script Hosts & Signature Catalog Files
 - By William Easton (@strawgate)
 - https://github.com/strawgate/Advisories/blob/main/Microsoft/VULN-051861.md

-------------------------------
### Defense, Policy Creation, Testing, & Research
 
#### WDAC Twitch Stream
 - Fantastic videos collection that covers WDAC Policy Creation/Enforcement/Bypass/Audit/Etc.
 - By Matt Graeber (@mattifestation)
 - https://www.youtube.com/playlist?list=PL2Xx-q-W5pKUNaNkakjZkLmfsNvMWPdNB

#### WDAC Policy Wizard
 - Documentation and tools to access Windows Defender Application Control (WDAC) technology
 - By Microsoft Docs
 - https://github.com/MicrosoftDocs/WDAC-Toolkit

#### WDACTools
 - A PowerShell module to facilitate building, configuring, deploying, and auditing Windows Defender Application Control (WDAC) policies
 - By Matt Graeber (@mattifestation)
 - https://github.com/mattifestation/WDACTools
 
#### WDACPolicies
 - A collection of Windows software baseline notes with corresponding Windows Defender Application Control (WDAC) policies
 - By Matt Graeber (@mattifestation)
 - https://github.com/mattifestation/WDACPolicies
 
#### Building a Windows Defender Application Control Lab
 - By FortyNorth Security (@FortyNorthSec)
 - https://fortynorthsecurity.com/blog/building-a-windows-defender-application-control-lab/
 
#### Documenting and Attacking a Windows Defender Application Control Feature the Hard Way — A Case Study in Security Research Methodology
 - By Matt Graeber (@mattifestation)
 - https://posts.specterops.io/documenting-and-attacking-a-windows-defender-application-control-feature-the-hard-way-a-case-73dd1e11be3a
 
#### WinAWL
 - Windows Application Control Notes and Sample Policies
 - By Brian in Pittsburgh (@arekfurt)
 - https://github.com/arekfurt/WinAWL

#### Exploit Monday Blog
 - By Matt Graeber (@mattifestation)
 - http://www.exploit-monday.com/

#### Quick Steps for Deploying a Policy & Setting Up a WDAC Test Machine
 - By Jimmy Bayne (@bohops)
 - https://github.com/bohops/Notes/tree/master/Windows/WDAC-DeviceGuard

#### Windows Defender Application Control (WDAC) Updates in 20H2 and Building a Simple, Secure Windows-only Policy
 - By Matt Graeber (@mattifestation)
 - https://mattifestation.medium.com/windows-defender-application-control-wdac-updates-in-20h2-and-building-a-simple-secure-4fd4ee86de4
