using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace testapi.Models
{
    public class UserRefreshToken
    {
		public int Id { get; set; }
		public string Username { get; set; }
		public string Password { get; set; }
		public string RefreshToken { get; set; }
	}
}
