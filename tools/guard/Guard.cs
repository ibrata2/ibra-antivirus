// IBRA ANTIVIRUS — behaviour guard (ibra-guard.exe)
// برمجة وتطوير ابراهيم الخزرجي — IBRAPROGRAM
//
// What it does (like the behaviour blockers in Kaspersky / ESET, without a kernel driver):
//  1. Launch guard   — every program started from Downloads / Desktop / Temp / AppData / USB that is not signed
//                      is paused the moment it starts, the app scans it, then it is resumed or killed.
//  2. Command guard  — PowerShell / mshta / cmd started with a download-and-run command (fake "I'm not a robot"
//                      pages, ClickFix) is killed at once.
//  3. Stealer guard  — Windows auditing is switched on for browser passwords/cookies (Chrome, Edge, Brave, Opera,
//                      Vivaldi, Yandex, Firefox), Telegram sessions, Discord tokens and crypto wallets; any unsigned
//                      program or script that touches them is killed within milliseconds, even a brand-new virus.
//  4. Ransomware guard — hidden bait files in your folders; whatever writes to them is killed before it reaches your files.
//
//  5. Self-protection — the guard runs as a SYSTEM service; it locks the app's main process so normal programs cannot
//                      kill it, and starts the app again if something closes it without the user's approval.
//
// Modes:  ibra-guard.exe --service                              (SYSTEM, started by the "IBRA ANTIVIRUS Guard" task)
//         ibra-guard.exe --connect <port> --token-file <file>   (elevated, older task)
//         ibra-guard.exe --stdio                                (not elevated: launch + command guard only)
//         ibra-guard.exe --ok                                   (does nothing: run elevated to confirm an administrator approved)
// Protocol: one JSON object per line. Commands from the app: "resume <pid>", "kill <pid>", "trust <path>", "ping",
//           "watch <kind>\t<label>\t<path>\t<allowed,exes>" (what to guard, sent by the app), "bait <folder>", "risky <folder>",
//           "safe <folder>", "apply", "bye" (the user really closed the app).
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace IbraAntivirus.Guard
{
    internal sealed class Target
    {
        public string Kind;                       // "credential" | "decoy"
        public string What;                       // short label: "Chrome passwords", "Telegram session"...
        public HashSet<string> Allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    }

    internal static class Program
    {
        const string VERSION = "1.1.0";
        static bool Admin, Stdio, Service, System;
        static volatile bool Bye, EverConnected;
        static int Port;
        static string Token = "";
        static readonly object OutLock = new object();
        static TextWriter Out;
        static volatile bool AppConnected;
        static readonly string SelfDir = Path.GetFullPath(AppDomain.CurrentDomain.BaseDirectory).TrimEnd('\\');
        static string AppDir;                                        // ...\IBRA ANTIVIRUS (two levels up from resources\vendor)
        static readonly ConcurrentDictionary<int, DateTime> Suspended = new ConcurrentDictionary<int, DateTime>();
        static readonly ConcurrentDictionary<string, bool> TrustCache = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        static readonly ConcurrentDictionary<string, bool> UserTrusted = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        static readonly ConcurrentDictionary<int, bool> Handled = new ConcurrentDictionary<int, bool>();
        static readonly List<KeyValuePair<string, Target>> Targets = new List<KeyValuePair<string, Target>>();   // path prefix -> target
        static int Protected, ProtectErrors;
        static volatile bool AuditOn;

        static readonly HashSet<string> ScriptHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "powershell.exe", "pwsh.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
            "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "wmic.exe", "autoit3.exe", "python.exe", "pythonw.exe", "node.exe", "conhost.exe",
            "bitsadmin.exe", "certutil.exe", "curl.exe", "msiexec.exe", "forfiles.exe", "finger.exe", "hh.exe", "cmstp.exe"
        };
        // processes that may read browser / Telegram data without being stopped (still must be validly signed)
        static readonly HashSet<string> GlobalAllow = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "ibra antivirus.exe", "ibra-guard.exe", "msmpeng.exe", "mpdefendercoreservice.exe", "searchprotocolhost.exe",
            "searchindexer.exe", "searchfilterhost.exe", "system", "registry", "svchost.exe", "lsass.exe", "dllhost.exe", "backgroundtaskhost.exe"
        };

        // ---------------------------------------------------------------- download-and-run command detection (keep in sync with browser-extension/rules.js)
        static readonly Regex Tool = new Regex(@"(powershell|pwsh|mshta|\bcmd(\.exe)?\s*/[ckr]|curl(\.exe)?\s|wget\s|bitsadmin|certutil|rundll32|regsvr32|msiexec|wscript|cscript|conhost|finger(\.exe)?\s|forfiles|\bstart\s+/min)", RegexOptions.IgnoreCase);
        static readonly Regex Evil = new Regex(@"(https?://|\\\\\d{1,3}\.\d|-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|\biex\b|invoke-(expression|webrequest|restmethod)|\biwr\b|\birm\b|downloadstring|downloadfile|-w(indowstyle)?\s+h(idden)?|-nop\b|\|\s*(iex|powershell|cmd)|\$env:temp|%temp%|appdata)", RegexOptions.IgnoreCase);
        static readonly Regex Fetch = new Regex(@"(https?://|\\\\\d{1,3}\.\d|downloadstring|downloadfile|net\.webclient|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|start-bitstransfer|bitsadmin\s+/transfer|certutil.{0,40}-urlcache)", RegexOptions.IgnoreCase);
        static readonly Regex Run = new Regex(@"(\biex\b|invoke-expression|\|\s*(iex|powershell|pwsh|cmd)|start-process|&\s*\(|\.invoke\(|mshta|rundll32|regsvr32|-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|msiexec\s+/[iq]|\.(exe|hta|msi|ps1|vbs|js|bat|cmd)\b)", RegexOptions.IgnoreCase);
        static readonly Regex Decoy = new Regex(@"(✅|✔|robot|captcha|verification|cloudflare|human|ray\s*id)", RegexOptions.IgnoreCase);
        static readonly Regex Enc = new Regex(@"-e(nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{20,})", RegexOptions.IgnoreCase);

        /// <summary>"block" when the command downloads and runs something.</summary>
        static string JudgeCommand(string cmd, bool fromRunDialog)
        {
            if (string.IsNullOrEmpty(cmd)) return null;
            var text = cmd;
            var m = Enc.Match(cmd);
            if (m.Success) { try { text += " " + Encoding.Unicode.GetString(Convert.FromBase64String(m.Groups[2].Value)); } catch { } }
            if (Fetch.IsMatch(text) && Run.IsMatch(text)) return "block";                 // download + execute, from anywhere
            if (Regex.IsMatch(text, @"mshta(\.exe)?\s+[""']?(https?:|javascript:|vbscript:)", RegexOptions.IgnoreCase)) return "block";
            if (fromRunDialog && Tool.IsMatch(text) && (Evil.IsMatch(text) || Decoy.IsMatch(text))) return "block";  // pasted into Win+R
            return null;
        }

        // ---------------------------------------------------------------- entry
        static int Main(string[] args)
        {
            string Arg(string n) { var i = Array.IndexOf(args, n); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
            if (args.Contains("--ok")) return 0;
            Stdio = args.Contains("--stdio");
            Service = args.Contains("--service");
            int.TryParse(Arg("--connect") ?? (Service ? "47220" : "0"), out Port);
            var tf = Arg("--token-file");
            if (tf != null) { try { Token = File.ReadAllText(tf).Trim(); } catch { } }
            Admin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            System = WindowsIdentity.GetCurrent().IsSystem;
            if (Service) Token = ServiceToken();
            try { AppDir = Path.GetFullPath(Path.Combine(SelfDir, "..", "..")).TrimEnd('\\'); } catch { AppDir = SelfDir; }
            Out = Stdio ? Console.Out : TextWriter.Null;
            Console.OutputEncoding = new UTF8Encoding(false);

            if (args.Contains("--judge"))       // self-test: ibra-guard --judge "<command>"
            { Console.WriteLine(JudgeCommand(Arg("--judge"), args.Contains("--run")) ?? "allow"); return 0; }

            if (Admin)
            {
                EnablePrivilege("SeSecurityPrivilege");
                EnablePrivilege("SeDebugPrivilege");
                EnablePrivilege("SeRestorePrivilege");
                EnablePrivilege("SeTakeOwnershipPrivilege");
                new Thread(StartAuditWatch) { IsBackground = true }.Start();
                new Thread(SuspectLoop) { IsBackground = true }.Start();
                if (Service) new Thread(SelfProtectLoop) { IsBackground = true }.Start();
            }
            StartProcessWatch();
            new Thread(SafetyLoop) { IsBackground = true }.Start();

            if (Stdio)
            {
                AppConnected = true;
                Hello();
                string line;
                while ((line = Console.In.ReadLine()) != null) Command(line);
                return 0;   // app closed: the guard stops with it
            }
            ConnectLoop();   // never returns
            return 0;
        }

        static void Hello() => Emit("{\"type\":\"hello\",\"version\":" + J(VERSION) + ",\"admin\":" + B(Admin) + ",\"token\":" + J(Token) + ",\"protected\":" + Protected + ",\"audit\":" + B(AuditOn) + ",\"pid\":" + Process.GetCurrentProcess().Id + "}");

        static void ConnectLoop()
        {
            while (true)
            {
                try
                {
                    using (var c = new TcpClient())
                    {
                        c.Connect("127.0.0.1", Port);
                        var s = c.GetStream();
                        var w = new StreamWriter(s, new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
                        lock (OutLock) Out = w;
                        AppConnected = true; EverConnected = true; Bye = false;
                        Hello();
                        var r = new StreamReader(s, Encoding.UTF8);
                        string line;
                        while ((line = r.ReadLine()) != null) Command(line);
                    }
                }
                catch { }
                AppConnected = false;
                lock (OutLock) Out = TextWriter.Null;
                ResumeAllPending();
                Thread.Sleep(3000);
            }
        }

        static void Command(string line)
        {
            var p = line.Trim().Split(new[] { ' ' }, 2);
            if (p.Length == 0) return;
            int pid;
            switch (p[0])
            {
                case "resume": if (p.Length > 1 && int.TryParse(p[1], out pid)) { Resume(pid); Suspended.TryRemove(pid, out _); } break;
                case "kill": if (p.Length > 1 && int.TryParse(p[1], out pid)) { Kill(pid); Suspended.TryRemove(pid, out _); } break;
                case "trust": if (p.Length > 1) UserTrusted[p[1].Trim()] = true; break;
                case "watch": if (p.Length > 1) lock (Plan) Plan.Add(p[1]); break;
                case "bait": if (p.Length > 1) lock (Plan) Plan.Add("bait\t" + p[1].Trim()); break;
                case "risky": if (p.Length > 1) lock (Roots) Roots.Add(p[1].Trim().TrimEnd('\\') + "\\"); break;
                case "safe": if (p.Length > 1) lock (Roots) Safe.Add(p[1].Trim().TrimEnd('\\') + "\\"); break;
                case "apply":
                    if (Admin) { List<string> plan; lock (Plan) { plan = Plan.ToList(); Plan.Clear(); } new Thread(() => Protect(plan)) { IsBackground = true }.Start(); }
                    break;
                case "bye": Bye = true; break;
                case "ping": Emit("{\"type\":\"pong\",\"admin\":" + B(Admin) + ",\"protected\":" + Protected + ",\"suspended\":" + Suspended.Count + "}"); break;
            }
        }

        // a paused program the app never answered about is let go after 20 s (never leave the user's programs frozen)
        static void SafetyLoop()
        {
            while (true)
            {
                Thread.Sleep(1000);
                foreach (var kv in Suspended.ToArray())
                    if ((DateTime.UtcNow - kv.Value).TotalSeconds > 20) { Resume(kv.Key); Suspended.TryRemove(kv.Key, out _); Emit("{\"type\":\"timeout\",\"pid\":" + kv.Key + "}"); }
            }
        }
        static void ResumeAllPending() { foreach (var kv in Suspended.ToArray()) { Resume(kv.Key); Suspended.TryRemove(kv.Key, out _); } }

        // ---------------------------------------------------------------- 1+2. program starts
        static void StartProcessWatch()
        {
            ManagementEventWatcher w = null;
            if (Admin)
            {
                try
                {
                    w = new ManagementEventWatcher(new WqlEventQuery("SELECT ProcessID, ParentProcessID, ProcessName FROM Win32_ProcessStartTrace"));
                    w.EventArrived += (s, e) =>
                    {
                        try
                        {
                            var pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
                            var ppid = Convert.ToInt32(e.NewEvent["ParentProcessID"]);
                            var name = Convert.ToString(e.NewEvent["ProcessName"]);
                            ThreadPool.QueueUserWorkItem(_ => OnStart(pid, ppid, name, null, null));
                        }
                        catch { }
                    };
                    w.Start();
                    Emit("{\"type\":\"watch\",\"mode\":\"trace\"}");
                    return;
                }
                catch { w = null; }
            }
            w = new ManagementEventWatcher(new WqlEventQuery("__InstanceCreationEvent", TimeSpan.FromMilliseconds(400), "TargetInstance ISA 'Win32_Process'"));
            w.EventArrived += (s, e) =>
            {
                try
                {
                    var t = (ManagementBaseObject)e.NewEvent["TargetInstance"];
                    var pid = Convert.ToInt32(t["ProcessId"]); var ppid = Convert.ToInt32(t["ParentProcessId"]);
                    var name = Convert.ToString(t["Name"]); var path = t["ExecutablePath"] as string; var cmd = t["CommandLine"] as string;
                    ThreadPool.QueueUserWorkItem(_ => OnStart(pid, ppid, name, path, cmd));
                }
                catch { }
            };
            w.Start();
            Emit("{\"type\":\"watch\",\"mode\":\"poll\"}");
        }

        static bool IsOurs(string path) => path != null && (path.StartsWith(SelfDir, StringComparison.OrdinalIgnoreCase) || (AppDir != null && AppDir.Length > 3 && path.StartsWith(AppDir, StringComparison.OrdinalIgnoreCase)));

        static void OnStart(int pid, int ppid, string name, string path, string cmd)
        {
            try
            {
                if (pid <= 4) return;
                var lname = (name ?? "").ToLowerInvariant();
                var parentPath = ImagePath(ppid);
                if (IsOurs(parentPath)) return;                      // started by IBRA itself
                if (ScriptHosts.Contains(lname))
                {
                    var parent = Path.GetFileName(parentPath ?? "").ToLowerInvariant();
                    bool fromRun = parent == "explorer.exe";      // Win+R / Run dialog / double-click
                    if (fromRun && Suspend(pid)) Suspended[pid] = DateTime.UtcNow;   // freeze while we read the command
                    if (cmd == null) cmd = CommandLine(pid);
                    var verdict = JudgeCommand(cmd, fromRun);
                    if (verdict == "block")
                    {
                        Kill(pid); Suspended.TryRemove(pid, out _);
                        Emit("{\"type\":\"blocked\",\"kind\":\"command\",\"pid\":" + pid + ",\"path\":" + J(path ?? ImagePath(pid) ?? name) + ",\"cmd\":" + J(Cut(cmd, 600)) + ",\"parent\":" + J(parentPath) + ",\"fromRun\":" + B(fromRun) + "}");
                    }
                    else if (Suspended.TryRemove(pid, out _)) Resume(pid);
                    return;
                }
                if (path == null) path = ImagePath(pid);
                if (path == null || IsOurs(path) || UserTrusted.ContainsKey(path)) return;
                if (!Risky(path)) return;
                if (!AppConnected) return;                           // nobody can scan it: let it run
                if (Trusted(path)) return;                            // validly signed
                if (!Suspend(pid)) return;
                Suspended[pid] = DateTime.UtcNow;
                Emit("{\"type\":\"launch\",\"pid\":" + pid + ",\"path\":" + J(path) + ",\"parent\":" + J(parentPath) + ",\"cmd\":" + J(Cut(cmd ?? "", 400)) + "}");
            }
            catch (Exception e) { Emit("{\"type\":\"error\",\"where\":\"start\",\"msg\":" + J(e.Message) + "}"); }
        }

        // folders a downloaded / dropped program runs from; the app sends the user's own folders ("risky ...")
        static readonly List<string> Roots = new List<string>();
        static readonly List<string> Safe = new List<string>();
        static readonly List<string> Plan = new List<string>();
        static Program()
        {
            string E(string v) => Environment.GetEnvironmentVariable(v) ?? "";
            var home = E("USERPROFILE");
            var list = new List<string> { E("PUBLIC"), E("ProgramData"), Path.Combine(E("windir"), "Temp"), Path.Combine(E("windir"), "Tasks") };
            if (!WindowsIdentity.GetCurrent().IsSystem)
                list.AddRange(new[] { Path.Combine(home, "Downloads"), Path.Combine(home, "Desktop"), Path.Combine(home, "Documents"), Path.Combine(home, "Music"),
                    Path.Combine(home, "Pictures"), Path.Combine(home, "Videos"), E("APPDATA"), E("LOCALAPPDATA"), Path.Combine(home, "AppData", "LocalLow"), E("TEMP") });
            Roots.AddRange(list.Where(x => x.Length > 3).Select(x => x.TrimEnd('\\') + "\\"));
            Safe.Add(Path.Combine(E("ProgramData"), "Microsoft", "Windows Defender") + "\\");
        }
        static bool Risky(string path)
        {
            string[] safe, roots; lock (Roots) { safe = Safe.ToArray(); roots = Roots.ToArray(); }
            if (path.IndexOf("\\Microsoft\\WindowsApps\\", StringComparison.OrdinalIgnoreCase) >= 0) return false;
            if (safe.Any(s => path.StartsWith(s, StringComparison.OrdinalIgnoreCase))) return false;
            if (roots.Any(r => path.StartsWith(r, StringComparison.OrdinalIgnoreCase))) return true;
            try { var root = Path.GetPathRoot(path); if (!string.IsNullOrEmpty(root) && new DriveInfo(root).DriveType == DriveType.Removable) return true; } catch { }
            return false;
        }

        // ---------------------------------------------------------------- 3+4. stealer + ransomware guard (Windows object-access auditing)
        static readonly SecurityIdentifier World = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

        static void AddTarget(string prefix, string kind, string what, params string[] allowed)
        {
            var t = new Target { Kind = kind, What = what };
            foreach (var a in allowed) t.Allowed.Add(a);
            lock (Targets) Targets.Add(new KeyValuePair<string, Target>(prefix.TrimEnd('\\'), t));
        }

        static void AuditFile(string path, FileSystemRights rights, AuditFlags flags = AuditFlags.Success)
        {
            try
            {
                if (!File.Exists(path)) return;
                var fs = File.GetAccessControl(path, AccessControlSections.Audit);
                fs.AddAuditRule(new FileSystemAuditRule(World, rights, flags));
                File.SetAccessControl(path, fs);
                Protected++;
            }
            catch { ProtectErrors++; }
        }
        static void AuditDir(string path, FileSystemRights rights)
        {
            try
            {
                if (!Directory.Exists(path)) return;
                var ds = Directory.GetAccessControl(path, AccessControlSections.Audit);
                ds.AddAuditRule(new FileSystemAuditRule(World, rights, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AuditFlags.Success));
                Directory.SetAccessControl(path, ds);
                Protected++;
            }
            catch { ProtectErrors++; }
        }

        // what to guard comes from the app (the guard file itself holds no list of other programs' data)
        //   "<kind>\t<label>\t<path>\t<allowed exes>"   kind: file | dir | area (an area only names who may read it)
        //   "bait\t<folder>"
        static void Protect(List<string> plan)
        {
            lock (Targets) Targets.Clear();
            Protected = 0; ProtectErrors = 0;
            var read = FileSystemRights.ReadData;
            var bait = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete;
            foreach (var line in plan)
            {
                var f = line.Split('\t');
                try
                {
                    if (f[0] == "bait" && f.Length > 1) { MakeBait(f[1].Trim(), bait); continue; }
                    if (f.Length < 3) continue;
                    var p = f[2].Trim();
                    var allowed = f.Length > 3 ? f[3].Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).ToArray() : new string[0];
                    if (f[0] == "area") { if (Directory.Exists(p)) AddTarget(p, "credential", f[1], allowed); }
                    else if (f[0] == "file") AuditFile(p, read);
                    else if (f[0] == "dir") AuditDir(p, read);
                }
                catch { ProtectErrors++; }
            }
            // File System auditing — language-independent GUID
            RunHidden("auditpol.exe", "/set /subcategory:{0CCE921D-69AE-11D9-BED3-505054503030} /success:enable /failure:enable");
            Emit("{\"type\":\"protected\",\"count\":" + Protected + ",\"errors\":" + ProtectErrors + "}");
        }

        // ransomware bait files (visible on purpose: Windows refuses overwriting a hidden file before any audit happens)
        static void MakeBait(string folder, FileSystemRights rights)
        {
            if (!Directory.Exists(folder)) return;
            foreach (var name in new[] { "!IBRA-guard.docx", "~IBRA-guard.jpg" })
            {
                var f = Path.Combine(folder, name);
                try
                {
                    if (File.Exists(f)) File.SetAttributes(f, FileAttributes.Normal);
                    else
                    {
                        var buf = new byte[48 * 1024]; new Random().NextBytes(buf);
                        if (name.EndsWith(".docx")) { buf[0] = 0x50; buf[1] = 0x4B; buf[2] = 3; buf[3] = 4; } else { buf[0] = 0xFF; buf[1] = 0xD8; buf[2] = 0xFF; }
                        File.WriteAllBytes(f, buf);
                    }
                    AddTarget(f, "decoy", "bait file");
                    AuditFile(f, rights, AuditFlags.Success | AuditFlags.Failure);
                    WatchBait(folder);
                }
                catch { ProtectErrors++; }
            }
        }

        // The audit event that names the culprit arrives up to a second late. A bait change is seen within milliseconds,
        // so at that moment every suspect (unsigned program from a user folder / Temp / USB, or a script host) is paused;
        // the culprit is killed when its audit event arrives and the others go on 3 s later.
        static readonly ConcurrentDictionary<string, FileSystemWatcher> BaitWatch = new ConcurrentDictionary<string, FileSystemWatcher>(StringComparer.OrdinalIgnoreCase);
        static readonly ConcurrentDictionary<int, bool> Frozen = new ConcurrentDictionary<int, bool>();
        static readonly ConcurrentDictionary<int, string> Suspects = new ConcurrentDictionary<int, string>();
        static void WatchBait(string folder)
        {
            if (BaitWatch.ContainsKey(folder)) return;
            try
            {
                var w = new FileSystemWatcher(folder) { NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName, IncludeSubdirectories = false, InternalBufferSize = 65536 };
                FileSystemEventHandler h = (s, e) => { if (e.Name != null && e.Name.IndexOf("IBRA-guard", StringComparison.OrdinalIgnoreCase) >= 0) FreezeSuspects(); };
                w.Changed += h; w.Deleted += h; w.Renamed += (s, e) => { if ((e.OldName ?? "").IndexOf("IBRA-guard", StringComparison.OrdinalIgnoreCase) >= 0) FreezeSuspects(); };
                w.EnableRaisingEvents = true;
                BaitWatch[folder] = w;
            }
            catch { }
        }
        static int FreezeBusy;
        static void FreezeSuspects()
        {
            if (Interlocked.Exchange(ref FreezeBusy, 1) == 1) return;
            try
            {
                var me = Process.GetCurrentProcess().Id;
                foreach (var kv in Suspects.ToArray())
                    if (kv.Key != me && !Frozen.ContainsKey(kv.Key) && Suspend(kv.Key)) Frozen[kv.Key] = true;
                new Thread(() =>
                {
                    Thread.Sleep(3000);
                    foreach (var pid in Frozen.Keys.ToArray()) { if (!Handled.ContainsKey(pid)) Resume(pid); Frozen.TryRemove(pid, out _); }
                    Interlocked.Exchange(ref FreezeBusy, 0);
                }) { IsBackground = true }.Start();
            }
            catch { Interlocked.Exchange(ref FreezeBusy, 0); }
        }
        // keeps the list of suspects ready, so pausing them takes no time
        static void SuspectLoop()
        {
            while (true)
            {
                try
                {
                    var alive = new HashSet<int>();
                    foreach (var pr in Process.GetProcesses())
                    {
                        using (pr)
                        {
                            var pid = pr.Id; if (pid <= 4) continue;
                            alive.Add(pid);
                            if (Suspects.ContainsKey(pid)) continue;
                            var img = ImagePath(pid); if (img == null || IsOurs(img) || UserTrusted.ContainsKey(img)) continue;
                            var n = Path.GetFileName(img).ToLowerInvariant();
                            if (n == "explorer.exe" || GlobalAllow.Contains(n)) continue;
                            if (ScriptHosts.Contains(n) && n != "conhost.exe") { Suspects[pid] = img; continue; }
                            if (Risky(img) && !Trusted(img)) Suspects[pid] = img;
                        }
                    }
                    foreach (var pid in Suspects.Keys.ToArray()) if (!alive.Contains(pid)) Suspects.TryRemove(pid, out _);
                }
                catch { }
                Thread.Sleep(700);
            }
        }

        // ---------------------------------------------------------------- 5. self-protection (service mode)
        static string DataDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "IBRA ANTIVIRUS");

        // random token the app must know; readable by users, writable only by SYSTEM / administrators
        static string ServiceToken()
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                var ds = new DirectorySecurity();
                ds.SetAccessRuleProtection(true, false);
                var inh = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inh, PropagationFlags.None, AccessControlType.Allow));
                ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inh, PropagationFlags.None, AccessControlType.Allow));
                ds.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, inh, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(DataDir, ds);
                var f = Path.Combine(DataDir, "guard.token");
                var t = File.Exists(f) ? File.ReadAllText(f).Trim() : "";
                if (t.Length < 32) { var b = new byte[24]; new System.Security.Cryptography.RNGCryptoServiceProvider().GetBytes(b); t = BitConverter.ToString(b).Replace("-", "").ToLowerInvariant(); File.WriteAllText(f, t); }
                return t;
            }
            catch { return ""; }
        }

        static readonly ConcurrentDictionary<int, bool> Locked = new ConcurrentDictionary<int, bool>(), Helpers = new ConcurrentDictionary<int, bool>();
        static DateTime GoneSince = DateTime.MinValue;

        static void SelfProtectLoop()
        {
            var appExe = Path.Combine(AppDir, "IBRA ANTIVIRUS.exe");
            while (true)
            {
                Thread.Sleep(1500);
                try
                {
                    bool running = false;
                    foreach (var pr in Process.GetProcessesByName("IBRA ANTIVIRUS"))
                    {
                        using (pr)
                        {
                            var img = ImagePath(pr.Id);
                            if (img == null || !img.Equals(appExe, StringComparison.OrdinalIgnoreCase)) continue;
                            if (Helpers.ContainsKey(pr.Id)) continue;
                            if (!Locked.ContainsKey(pr.Id) && (CommandLine(pr.Id) ?? "").Contains("--type=")) { Helpers[pr.Id] = true; continue; }   // a Chromium helper process
                            running = true;
                            if (!Locked.ContainsKey(pr.Id)) Locked[pr.Id] = LockProcess(pr.Id);
                        }
                    }
                    var me = Process.GetCurrentProcess().Id;
                    if (!Locked.ContainsKey(me)) Locked[me] = LockProcess(me);
                    if (Locked.Count > 500) Locked.Clear(); if (Helpers.Count > 2000) Helpers.Clear();
                    if (running || Bye || !EverConnected) { GoneSince = DateTime.MinValue; continue; }
                    if (GoneSince == DateTime.MinValue) { GoneSince = DateTime.UtcNow; continue; }
                    if ((DateTime.UtcNow - GoneSince).TotalSeconds < 4) continue;
                    // the app was closed without the user's approval (killed): start it again in the user's session
                    GoneSince = DateTime.UtcNow.AddSeconds(30);   // at most one try every ~30 s
                    var ok = StartInUserSession("\"" + appExe + "\" --hidden --restarted", AppDir);
                    Emit("{\"type\":\"restarted\",\"ok\":" + B(ok) + "}");
                }
                catch { }
            }
        }

        // owner = Administrators, normal users may only look at the process — not end, pause, change or inject into it
        [DllImport("advapi32.dll", SetLastError = true)] static extern int SetSecurityInfo(IntPtr h, int type, int info, byte[] owner, byte[] group, byte[] dacl, byte[] sacl);
        static bool LockProcess(int pid)
        {
            var h = OpenProcess(0x00040000 /*WRITE_DAC*/ | 0x00080000 /*WRITE_OWNER*/ | 0x00020000 /*READ_CONTROL*/, false, pid);
            if (h == IntPtr.Zero) return false;
            try
            {
                var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                var acl = new RawAcl(GenericAcl.AclRevision, 4);
                acl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x1FFFFF, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), false, null));
                acl.InsertAce(1, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x1FFFFF, admins, false, null));
                acl.InsertAce(2, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x00020000, new SecurityIdentifier("S-1-3-4") /*OWNER RIGHTS*/, false, null));
                acl.InsertAce(3, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x00100000 | 0x1000 | 0x0400 | 0x0010 | 0x00020000,
                    new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), false, null));   // SYNCHRONIZE, QUERY, VM_READ, READ_CONTROL
                var dacl = new byte[acl.BinaryLength]; acl.GetBinaryForm(dacl, 0);
                var owner = new byte[admins.BinaryLength]; admins.GetBinaryForm(owner, 0);
                return SetSecurityInfo(h, 6 /*SE_KERNEL_OBJECT*/, 0x1 /*OWNER*/ | 0x4 /*DACL*/ | unchecked((int)0x80000000) /*PROTECTED_DACL*/, owner, null, dacl, null) == 0;
            }
            catch { return false; }
            finally { CloseHandle(h); }
        }

        [DllImport("kernel32.dll")] static extern uint WTSGetActiveConsoleSessionId();
        [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSQueryUserToken(uint session, out IntPtr token);
        [DllImport("userenv.dll", SetLastError = true)] static extern bool CreateEnvironmentBlock(out IntPtr env, IntPtr token, bool inherit);
        [DllImport("userenv.dll")] static extern bool DestroyEnvironmentBlock(IntPtr env);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO { public int cb; public string lpReserved, lpDesktop, lpTitle; public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
        [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessAsUser(IntPtr token, string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, int flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

        static bool StartInUserSession(string cmd, string dir)
        {
            if (!System) return false;
            var sid = WTSGetActiveConsoleSessionId();
            if (sid == 0xFFFFFFFF || !WTSQueryUserToken(sid, out var tok)) return false;
            IntPtr env = IntPtr.Zero;
            try
            {
                CreateEnvironmentBlock(out env, tok, false);
                var si = new STARTUPINFO { cb = Marshal.SizeOf(typeof(STARTUPINFO)), lpDesktop = "winsta0\\default" };
                if (!CreateProcessAsUser(tok, null, new StringBuilder(cmd), IntPtr.Zero, IntPtr.Zero, false, 0x00000400 /*UNICODE_ENVIRONMENT*/, env, dir, ref si, out var pi)) return false;
                CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
                return true;
            }
            finally { if (env != IntPtr.Zero) DestroyEnvironmentBlock(env); CloseHandle(tok); }
        }

        static Target MatchTarget(string obj, out string prefix)
        {
            prefix = null;
            if (string.IsNullOrEmpty(obj)) return null;
            lock (Targets)
                foreach (var kv in Targets)
                    if (obj.Equals(kv.Key, StringComparison.OrdinalIgnoreCase) || obj.StartsWith(kv.Key + "\\", StringComparison.OrdinalIgnoreCase)) { prefix = kv.Key; return kv.Value; }
            return null;
        }

        static void StartAuditWatch()
        {
            try
            {
                // 4663 = access done, 4656 = access requested (we need it for refused writes to the bait files)
                var q = new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=4663 or EventID=4656)]]");
                var w = new EventLogWatcher(q);
                w.EventRecordWritten += (s, e) => { try { if (e.EventRecord != null) OnAccess(e.EventRecord); } catch { } };
                w.Enabled = true;
                AuditOn = true;
                Emit("{\"type\":\"audit\",\"on\":true}");
            }
            catch (Exception e) { Emit("{\"type\":\"audit\",\"on\":false,\"error\":" + J(e.Message) + "}"); }
        }

        static void OnAccess(EventRecord rec)
        {
            var pr = rec.Properties;
            bool request = rec.Id == 4656;
            if (pr.Count < (request ? 16 : 12)) return;
            var obj = pr[6].Value as string;
            var t = MatchTarget(obj, out _);
            if (t == null) return;
            if (request && t.Kind != "decoy") return;                 // credential stores: only real reads count
            long mask = 0; try { mask = Convert.ToInt64(pr[request ? 11 : 9].Value); } catch { }
            int pid = 0; try { pid = (int)Convert.ToInt64(pr[request ? 14 : 10].Value); } catch { }
            var img = pr[request ? 15 : 11].Value as string ?? "";
            if (request && (mask & 0x10006) == 0) return;             // only WriteData / AppendData / Delete attempts
            var lname = Path.GetFileName(img).ToLowerInvariant();
            if (pid <= 4 || IsOurs(img) || UserTrusted.ContainsKey(img)) return;
            if (t.Kind == "decoy")
            {
                if (lname == "explorer.exe" || GlobalAllow.Contains(lname)) return;      // the user deleting/renaming it in Explorer
                if (!Handled.TryAdd(pid, true)) return;
                Suspend(pid); Kill(pid);
                Emit("{\"type\":\"blocked\",\"kind\":\"ransomware\",\"pid\":" + pid + ",\"path\":" + J(img) + ",\"file\":" + J(obj) + ",\"mask\":" + mask + "}");
                return;
            }
            // credential store
            bool script = ScriptHosts.Contains(lname);
            if (!script && (t.Allowed.Contains(lname) || GlobalAllow.Contains(lname)) && Trusted(img)) return;
            if (!script && Trusted(img))
            {
                // signed program reading another program's passwords: report, do not stop (password managers, backup tools)
                if (Handled.TryAdd(pid, true)) Emit("{\"type\":\"access\",\"pid\":" + pid + ",\"path\":" + J(img) + ",\"file\":" + J(obj) + ",\"what\":" + J(t.What) + "}");
                return;
            }
            if (!Handled.TryAdd(pid, true)) return;
            Suspend(pid); Kill(pid);
            Emit("{\"type\":\"blocked\",\"kind\":\"stealer\",\"pid\":" + pid + ",\"path\":" + J(img) + ",\"file\":" + J(obj) + ",\"what\":" + J(t.What) + ",\"script\":" + B(script) + "}");
        }

        // ---------------------------------------------------------------- Windows helpers
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder sb, ref int size);
        [DllImport("ntdll.dll")] static extern int NtSuspendProcess(IntPtr h);
        [DllImport("ntdll.dll")] static extern int NtResumeProcess(IntPtr h);
        [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr h, uint code);
        const int PROCESS_TERMINATE = 0x0001, PROCESS_SUSPEND_RESUME = 0x0800, PROCESS_QUERY_LIMITED = 0x1000;

        static string ImagePath(int pid)
        {
            if (pid <= 4) return null;
            var h = OpenProcess(PROCESS_QUERY_LIMITED, false, pid);
            if (h == IntPtr.Zero) return null;
            try { var sb = new StringBuilder(1024); int n = sb.Capacity; return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString() : null; }
            finally { CloseHandle(h); }
        }
        static bool Suspend(int pid) { var h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid); if (h == IntPtr.Zero) return false; try { return NtSuspendProcess(h) == 0; } finally { CloseHandle(h); } }
        static void Resume(int pid) { var h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid); if (h == IntPtr.Zero) return; try { NtResumeProcess(h); } finally { CloseHandle(h); } }
        static void Kill(int pid)
        {
            var h = OpenProcess(PROCESS_TERMINATE, false, pid);
            if (h != IntPtr.Zero) { try { TerminateProcess(h, 0xC0DE); } finally { CloseHandle(h); } return; }
            try { Process.GetProcessById(pid).Kill(); } catch { }
        }
        static string CommandLine(int pid)
        {
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT CommandLine FROM Win32_Process WHERE ProcessId=" + pid))
                    foreach (ManagementObject o in s.Get()) return o["CommandLine"] as string;
            }
            catch { }
            return null;
        }
        static void RunHidden(string exe, string args)
        {
            try { using (var p = Process.Start(new ProcessStartInfo(exe, args) { CreateNoWindow = true, UseShellExecute = false, WindowStyle = ProcessWindowStyle.Hidden })) p.WaitForExit(10000); } catch { }
        }

        // Authenticode: is the file validly signed?
        static bool Trusted(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                if (!fi.Exists) return false;
                var key = path + "|" + fi.Length + "|" + fi.LastWriteTimeUtc.Ticks;
                return TrustCache.GetOrAdd(key, _ => VerifySignature(path));
            }
            catch { return false; }
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO { public int cbStruct; public string pcwszFilePath; public IntPtr hFile; public IntPtr pgKnownSubject; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_DATA
        {
            public int cbStruct; public IntPtr pPolicyCallbackData; public IntPtr pSIPClientData; public int dwUIChoice; public int fdwRevocationChecks;
            public int dwUnionChoice; public IntPtr pFile; public int dwStateAction; public IntPtr hWVTStateData; public IntPtr pwszURLReference;
            public int dwProvFlags; public int dwUIContext; public IntPtr pSignatureSettings;
        }
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)] static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref WINTRUST_DATA data);
        static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        static bool VerifySignature(string path)
        {
            var fi = new WINTRUST_FILE_INFO { cbStruct = Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = path };
            var pFile = Marshal.AllocHGlobal(Marshal.SizeOf(fi));
            try
            {
                Marshal.StructureToPtr(fi, pFile, false);
                var d = new WINTRUST_DATA
                {
                    cbStruct = Marshal.SizeOf(typeof(WINTRUST_DATA)), dwUIChoice = 2 /*none*/, fdwRevocationChecks = 0, dwUnionChoice = 1 /*file*/,
                    pFile = pFile, dwStateAction = 0, dwProvFlags = 0x1000 /*cache only url retrieval*/ | 0x80 /*revocation check none*/
                };
                return WinVerifyTrust(new IntPtr(-1), WINTRUST_ACTION_GENERIC_VERIFY_V2, ref d) == 0;
            }
            catch { return false; }
            finally { Marshal.FreeHGlobal(pFile); }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)] struct LUID { public uint Low; public int High; }
        [StructLayout(LayoutKind.Sequential, Pack = 4)] struct TOKEN_PRIVILEGES { public int Count; public LUID Luid; public int Attr; }
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr h, int access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValue(string sys, string name, out LUID luid);
        [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES p, int len, IntPtr prev, IntPtr ret);
        static void EnablePrivilege(string name)
        {
            try
            {
                if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out var tok)) return;
                try { if (!LookupPrivilegeValue(null, name, out var luid)) return; var tp = new TOKEN_PRIVILEGES { Count = 1, Luid = luid, Attr = 2 }; AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero); }
                finally { CloseHandle(tok); }
            }
            catch { }
        }

        // ---------------------------------------------------------------- output
        static void Emit(string json) { lock (OutLock) { try { Out.WriteLine(json); Out.Flush(); } catch { } } }
        static string J(string s) => s == null ? "null" : "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", " ").Replace("\n", " ").Replace("\t", " ") + "\"";
        static string B(bool b) => b ? "true" : "false";
        static string Cut(string s, int n) => s == null ? null : s.Length > n ? s.Substring(0, n) : s;
    }
}
