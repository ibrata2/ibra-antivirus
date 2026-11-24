using System; using System.IO; using System.Runtime.InteropServices;
class K { [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(int a, bool i, int p);
  [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr h, uint c);
  static void Main(string[] a) { int pid = int.Parse(a[0]); var h = OpenProcess(1, false, pid); string r;
    if (h == IntPtr.Zero) r = "open-denied err=" + Marshal.GetLastWin32Error(); else r = TerminateProcess(h, 1) ? "KILLED" : "terminate-failed err=" + Marshal.GetLastWin32Error();
    File.WriteAllText(a[1], r); } }
