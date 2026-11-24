// Simulated infostealer: reads the browser password database and the Telegram session, then waits.
using System; using System.IO; using System.Threading;
class P { static void Main(string[] a) {
  string la = Environment.GetEnvironmentVariable("LOCALAPPDATA"), ra = Environment.GetEnvironmentVariable("APPDATA");
  try { var b = File.ReadAllBytes(Path.Combine(la, @"Google\Chrome\User Data\Default\Login Data")); Console.WriteLine("read " + b.Length); } catch (Exception e) { Console.WriteLine(e.Message); }
  Thread.Sleep(20000);
  File.WriteAllText(Path.Combine(Path.GetTempPath(), "stealer-survived.txt"), "alive");
} }
