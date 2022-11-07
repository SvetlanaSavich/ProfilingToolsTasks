// See https://aka.ms/new-console-template for more information
using System.Diagnostics;
using System.Security.Cryptography;

var password = "Password String";
var rng = new RNGCryptoServiceProvider();
var salt = new byte[32];
rng.GetNonZeroBytes(salt);

var stopWatch = new Stopwatch();

stopWatch.Start();
var generatedHash = GeneratePasswordHashUsingSalt(password, salt);
stopWatch.Stop();
Console.WriteLine($"GeneratePasswordHashUsingSalt: {stopWatch.Elapsed.Milliseconds}");

stopWatch.Restart();
var generatedHashImproved = GeneratePasswordHashUsingSaltImproved(password, salt);
stopWatch.Stop();
Console.WriteLine($"GeneratePasswordHashUsingSaltImproved: {stopWatch.Elapsed.Milliseconds}");

Console.ReadKey();

 string GeneratePasswordHashUsingSalt(string passwordText, byte[] salt)
{

    var iterate = 10000;
    var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, iterate);
    byte[] hash = pbkdf2.GetBytes(20);

    byte[] hashBytes = new byte[36];
    Array.Copy(salt, 0, hashBytes, 0, 16);
    Array.Copy(hash, 0, hashBytes, 16, 20);

    var passwordHash = Convert.ToBase64String(hashBytes);

    return passwordHash;
}

string GeneratePasswordHashUsingSaltImproved(string passwordText, byte[] salt)
{

    var iterate = 10000;
    byte[] hash;

    using (var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, iterate))
    {
        hash = pbkdf2.GetBytes(20);
    }

    byte[] hashBytes = new byte[36];

    Buffer.BlockCopy(salt, 0, hashBytes, 0, 16);
    Buffer.BlockCopy(hash, 0, hashBytes, 16, 20);

    var passwordHash = Convert.ToBase64String(hashBytes);

    return passwordHash;
}
