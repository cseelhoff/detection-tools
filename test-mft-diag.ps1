<#
.SYNOPSIS
    Diagnostic: test MFT path resolution with a small sample
#>

$mftSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

public class MftDiag2
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
        ref MFT_ENUM_DATA_V0 lpInBuffer, int nInBufferSize,
        IntPtr lpOutBuffer, int nOutBufferSize, out int lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint GENERIC_READ = 0x80000000;
    private const uint FILE_SHARE_READ = 0x01;
    private const uint FILE_SHARE_WRITE = 0x02;
    private const uint OPEN_EXISTING = 3;
    private const uint FSCTL_ENUM_USN_DATA = 0x000900B3;
    private const long FRN_MASK = 0x0000FFFFFFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    private struct MFT_ENUM_DATA_V0
    {
        public long StartFileReferenceNumber;
        public long LowUsn;
        public long HighUsn;
    }

    public static void Diagnose(string volumeLetter)
    {
        var dirNames = new Dictionary<long, string>();
        var dirParents = new Dictionary<long, long>();
        int totalFiles = 0;
        int totalDirs = 0;
        string volumePath = "\\\\.\\" + volumeLetter + ":";

        // Sample some specific files to track
        var trackFiles = new List<string> { "cmd.exe", "notepad.exe", "powershell.exe", "explorer.exe" };
        var trackedFileParents = new Dictionary<string, long>();

        IntPtr hVolume = CreateFile(volumePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (hVolume == new IntPtr(-1))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to open volume");

        try
        {
            int bufferSize = 2 * 1024 * 1024;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                var mftData = new MFT_ENUM_DATA_V0();
                mftData.StartFileReferenceNumber = 0;
                mftData.LowUsn = 0;
                mftData.HighUsn = long.MaxValue;
                int bytesReturned;

                int batches = 0;
                while (DeviceIoControl(hVolume, FSCTL_ENUM_USN_DATA,
                    ref mftData, Marshal.SizeOf(mftData), buffer, bufferSize, out bytesReturned, IntPtr.Zero))
                {
                    batches++;
                    int offset = 8;
                    while (offset < bytesReturned)
                    {
                        int recordLen = Marshal.ReadInt32(buffer, offset);
                        if (recordLen == 0) break;

                        long rawFrn = Marshal.ReadInt64(buffer, offset + 8);
                        long rawParentFrn = Marshal.ReadInt64(buffer, offset + 16);
                        long frn = rawFrn & FRN_MASK;
                        long parentFrn = rawParentFrn & FRN_MASK;
                        int attrs = Marshal.ReadInt32(buffer, offset + 52);
                        int fnLength = Marshal.ReadInt16(buffer, offset + 56);
                        int fnOffset = Marshal.ReadInt16(buffer, offset + 58);
                        string fn = Marshal.PtrToStringUni(
                            new IntPtr(buffer.ToInt64() + offset + fnOffset), fnLength / 2);

                        if ((attrs & 0x10) != 0)
                        {
                            totalDirs++;
                            dirNames[frn] = fn;
                            dirParents[frn] = parentFrn;

                            // Debug: print some well-known directories
                            if (fn == "System32" || fn == "Windows" || fn == "Program Files" || fn == "Users")
                            {
                                Console.WriteLine("DIR: frn={0} parentFrn={1} name={2} rawFrn=0x{3:X} rawParent=0x{4:X}",
                                    frn, parentFrn, fn, rawFrn, rawParentFrn);
                            }
                        }
                        else
                        {
                            totalFiles++;
                            foreach (var tf in trackFiles)
                            {
                                if (fn.Equals(tf, StringComparison.OrdinalIgnoreCase) && !trackedFileParents.ContainsKey(fn))
                                {
                                    trackedFileParents[fn] = parentFrn;
                                    Console.WriteLine("FILE: frn={0} parentFrn={1} name={2}", frn, parentFrn, fn);
                                }
                            }
                        }
                        offset += recordLen;
                    }
                    mftData.StartFileReferenceNumber = Marshal.ReadInt64(buffer, 0);
                    if (batches > 200) break; // limit for diagnostics
                }
                Console.WriteLine("\nScan: {0} batches, {1} dirs, {2} files (limited scan)", batches, totalDirs, totalFiles);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { CloseHandle(hVolume); }

        // Test path resolution
        Console.WriteLine("\n--- Path Resolution Test ---");
        Console.WriteLine("Root (FRN 5) in dirNames: {0}", dirNames.ContainsKey(5));
        Console.WriteLine("Root (FRN 5) in dirParents: {0}", dirParents.ContainsKey(5));
        if (dirNames.ContainsKey(5)) Console.WriteLine("Root name: '{0}'", dirNames[5]);

        foreach (var kvp in trackedFileParents)
        {
            Console.WriteLine("\nResolving path for: {0} (parentFRN={1})", kvp.Key, kvp.Value);
            long cur = kvp.Value;
            for (int i = 0; i < 10; i++)
            {
                bool inDirNames = dirNames.ContainsKey(cur);
                bool inDirParents = dirParents.ContainsKey(cur);
                string name = inDirNames ? dirNames[cur] : "???";
                long parent = inDirParents ? dirParents[cur] : -1;
                Console.WriteLine("  step {0}: FRN={1} name='{2}' parent={3} (inNames={4} inParents={5})",
                    i, cur, name, parent, inDirNames, inDirParents);
                if (cur == 5 || !inDirParents || parent == cur) break;
                cur = parent;
            }
        }
    }
}
'@

if (-not ([System.Management.Automation.PSTypeName]'MftDiag2').Type) {
    Add-Type -TypeDefinition $mftSource -Language CSharp
}
[MftDiag2]::Diagnose("C")
