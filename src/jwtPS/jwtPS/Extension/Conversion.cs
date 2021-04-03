using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace jwtPS.Extension
{
    public static class Conversion
    {
        /// <summary>
        /// This method converts a hashtable to a dictionary.
        /// </summary>
        /// <typeparam name="K"></typeparam>
        /// <typeparam name="V"></typeparam>
        /// <param name="Table"></param>
        /// <returns>Dictionary</returns>
        public static Dictionary<K, V> ToDictionary<K, V>(this Hashtable Table)
        {
            return Table
                .Cast<DictionaryEntry>()
                .ToDictionary(kvp => (K)kvp.Key, kvp => (V)kvp.Value);
        }
        /// <summary>
        /// This method converts a string to a RSA class.
        /// </summary>
        /// <param name="Key"></param>
        /// <returns>RSA</returns>
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
        /// <summary>
        /// This methods converts a string to an ECDsa class.
        /// </summary>
        /// <param name="Key"></param>
        /// <returns>ECDsa</returns>
        public static ECDsa ToECDsa(this string Key)
        {
            var regex = @"(-----(BEGIN|END) \w* \w* KEY-----)|(-----(BEGIN|END) \w* KEY-----)";
            var cleankey = Regex.Replace(Key, regex, string.Empty);
            var bytes = Convert.FromBase64String(cleankey);
            var ecdsa = ECDsa.Create();
            if (Key.Contains("PUBLIC"))
            {
                ecdsa.ImportSubjectPublicKeyInfo(bytes, out _);
                return ecdsa;
            }
            else if (Key.Contains("PRIVATE"))
            {
                ecdsa.ImportECPrivateKey(bytes, out _);
                return ecdsa;
            }
            else
            {
                throw new ArgumentOutOfRangeException("The string cannot be classified as either private or public key.");
            }
        }
        /// <summary>
        /// This methods decodes a Base64 string.
        /// </summary>
        /// <param name="Input"></param>
        /// <returns>String</returns>
        public static object FromBase64(this string Input)
        {
            var base64 = Input.Replace('-', '+').Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 1:
                    {
                        base64 = base64.Substring(0, base64.Length - 1);
                        break;
                    }
                case 2:
                    {
                        base64 += "==";
                        break;
                    }
                case 3:
                    {
                        base64 += "=";
                        break;
                    }
                default:
                    break;
            }
            var decode = Encoding.UTF8.GetString(Convert.FromBase64String(base64));
            byte[] jsonUtf8Bytes;
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };
            jsonUtf8Bytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(decode, options);
            return Encoding.UTF8.GetString(jsonUtf8Bytes);
            //return JsonConvert.DeserializeObject(decode);
        }
    }
}
