# (v1.1.0) change: aspart of this update, the launcher_stub has been rewritten from C to Nim for making it easier and better to maintain for me
when defined(windows):
  import os, strutils

  # define necessary winapi structures manually to avoid requiring external libraries
  type
    STARTUPINFO = object
      cb: int32
      lpReserved, lpDesktop, lpTitle: cstring
      dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars: int32
      dwFillAttribute, dwFlags: int32
      wShowWindow, cbReserved2: int16
      lpReserved2: pointer
      hStdInput, hStdOutput, hStdError: int
    PROCESS_INFORMATION = object
      hProcess, hThread: int
      dwProcessId, dwThreadId: int32

  proc CreateProcessA(lpApplicationName: cstring, lpCommandLine: cstring,
                      lpProcessAttributes: pointer, lpThreadAttributes: pointer,
                      bInheritHandles: int32, dwCreationFlags: int32,
                      lpEnvironment: pointer, lpCurrentDirectory: cstring,
                      lpStartupInfo: var STARTUPINFO,
                      lpProcessInformation: var PROCESS_INFORMATION): int32 {.stdcall, dynlib: "kernel32", importc.}
  
  proc WaitForSingleObject(hHandle: int, dwMilliseconds: int32): int32 {.stdcall, dynlib: "kernel32", importc.}
  proc GetExitCodeProcess(hProcess: int, lpExitCode: var int32): int32 {.stdcall, dynlib: "kernel32", importc.}
  proc CloseHandle(hObject: int): int32 {.stdcall, dynlib: "kernel32", importc.}

  const configMarker = "[XPPB_CONFIG]"

  proc main() =
    # 1. read the end of our own executable file
    let appPath = getAppFilename()
    var file: File
    if not open(file, appPath, fmRead):
      quit(1)
    
    let size = file.getFileSize()
    let readSize = min(size, 5242880)
    file.setFilePos(size - readSize)
    let tail = file.readStr(int(readSize))
    close(file)

    # 2. locate the injected configuration payload
    let markerIdx = tail.rfind(configMarker)
    if markerIdx == -1:
      quit("Fatal: Missing XPPB configuration payload. Corrupt executable.", 1)
    
    # extract string starting after configMarker
    let rawPayload = tail[markerIdx + configMarker.len .. ^1]
    let parts = rawPayload.split('|')
    if parts.len < 3:
      quit("Fatal: Invalid XPPB payload format.", 1)
    
    let pyExe = parts[0]
    let entryPoint = parts[1]
        
    # extract only the first character ('0' or '1') to ignore trailing signtool certificates
    let hideConsole = parts[2][0] == '1'

    # 3. construct the command line 
    let exeDir = getAppDir()
    var cmdLine = "\"" & exeDir & "\\python\\" & pyExe & "\" \"" & exeDir & "\\" & entryPoint & "\""
    
    # append any command line arguments passed by the user
    for arg in commandLineParams():
      cmdLine.add(" " & quoteShell(arg))

    # 4. launch the python process using WinAPI
    var si: STARTUPINFO
    si.cb = int32(sizeof(STARTUPINFO))
    var pi: PROCESS_INFORMATION

    let creationFlags: int32 = if hideConsole: 0x08000000 else: 0 # CREATE_NO_WINDOW

    if CreateProcessA(nil, cmdLine.cstring, nil, nil, 0, creationFlags, nil, nil, si, pi) != 0:
      discard WaitForSingleObject(pi.hProcess, -1) # Wait infinitely
      var exitCode: int32
      discard GetExitCodeProcess(pi.hProcess, exitCode)
      discard CloseHandle(pi.hProcess)
      discard CloseHandle(pi.hThread)
      quit(int(exitCode))
    else:
      quit(1)

  main()
