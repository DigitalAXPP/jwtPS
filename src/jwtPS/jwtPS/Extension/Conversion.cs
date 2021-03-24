using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

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
            var bytes = Convert.FromBase64String(Key);
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(bytes, out _);
        }
    }
}
