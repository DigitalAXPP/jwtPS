﻿using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace jwtPS.Class
{
    public class Header
    {
        const string typ = "JWT";
        private string alg { get; set; }

        public Header(string Algorithm)
        {
            alg = Algorithm;
        }
        /// <summary>
        /// This methods returns the JWT header encrypted in Base 64.
        /// </summary>
        /// <returns>string</returns>
        public string Create()
        {
            var dict = new Dictionary<string, string>()
            {
                { "typ", typ },
                { "alg", alg }
            };
            var json = JsonConvert.SerializeObject(dict);
            var bytes = Encoding.UTF8.GetBytes(json);
            return Convert.ToBase64String(bytes);
        }
    }
}
