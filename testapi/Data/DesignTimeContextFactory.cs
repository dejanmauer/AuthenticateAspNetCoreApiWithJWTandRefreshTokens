using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace testapi.Data
{
	public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
	{

		public ApplicationDbContext CreateDbContext(string[] args)
		{
			var builder = new DbContextOptionsBuilder<ApplicationDbContext>();
			var connectionString = "Server=(localdb)\\mssqllocaldb;Database=ApiExample;Trusted_Connection=True;MultipleActiveResultSets=true";
			builder.UseSqlServer(connectionString);
			return new ApplicationDbContext(builder.Options);
		}
	}
}