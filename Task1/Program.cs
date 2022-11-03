﻿// See https://aka.ms/new-console-template for more information
using System.Security.Cryptography;

var rng = new RNGCryptoServiceProvider();
var salt = new byte[32];
rng.GetNonZeroBytes(salt);

var generatedHash = GeneratePasswordHashUsingSalt("Password String", salt);

Console.WriteLine(generatedHash);

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