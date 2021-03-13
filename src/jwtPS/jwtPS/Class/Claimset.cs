using Newtonsoft.Json;
using System;
using System.Collections;
using System.Text;

namespace jwtPS.Class
{
    public class Claimset
    {
        public string Create(Hashtable Payload)
        {
            var json = JsonConvert.SerializeObject(Payload);
            var bytes = Encoding.UTF8.GetBytes(json);
            return Convert.ToBase64String(bytes);
        }
    }
}
