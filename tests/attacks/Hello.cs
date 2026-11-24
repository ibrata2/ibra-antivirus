// A normal unsigned program: must run normally.
using System; using System.IO;
class P { static void Main() { File.WriteAllText(Path.Combine(Path.GetTempPath(), "hello-ran.txt"), "ok " + DateTime.Now); } }
