using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace jwtPS.Extension
{
    public static class Conversion
    {
        public static Dictionary<K, V> ToDictionary<K, V>(this Hashtable Table)
        {
            return Table
                .Cast<DictionaryEntry>()
                .ToDictionary(kvp => (K)kvp.Key, kvp => (V)kvp.Value);
        }
        public static RSA ToRSA(this string Key)
        {
            var regex = @"(-----(BEGIN|END) \w* \w* KEY-----)|(-----(BEGIN|END) \w* KEY-----)";
            var cleankey = Regex.Replace(Key, regex, string.Empty);
            var bytes = Convert.FromBase64String(cleankey);
            var rsa = RSA.Create();
            if (Key.Contains("PUBLIC"))
            {
                rsa.ImportSubjectPublicKeyInfo(bytes, out _);
                return rsa;
            }
            else if (Key.Contains("PRIVATE"))
            {
                rsa.ImportPkcs8PrivateKey(bytes, out _);
                return rsa;
            }
            else
            {
                throw new ArgumentOutOfRangeException("The string cannot be classified as either private or public key.");
            }
        }
    }
}
