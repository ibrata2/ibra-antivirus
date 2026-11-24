// Simulated wallet stealer with the extension IDs real stealers carry (caught by YARA when launched).
using System; using System.IO; using System.Threading;
class P { static string[] ids = { "nkbihfbeogaeaoehlefnkodbefgpgknn", "bfnaelmomeimhlpmgjnjophhpkkoljpa", "ibnejdfjmmkpcnlpebklmnkoeoihofec", "egjidjbpglichdcondbcbdnbeeppgdph", "hnfanknocfeofbddgcijnmhnfnkdnaad", "fhbohimaelbohpjbbldcngcnapndodjp" };
  static void Main() { Thread.Sleep(15000); File.WriteAllText(Path.Combine(Path.GetTempPath(), "wallet-survived.txt"), string.Join(",", ids)); } }
