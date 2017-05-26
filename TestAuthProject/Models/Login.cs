using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace TestAuth.Models
{
    public class Login
    {
        public string Name { get; set; }

        public string Password { get; set; }

        public string Encrypt { get; set; }

        public string Decrypt { get; set; }

    }
}