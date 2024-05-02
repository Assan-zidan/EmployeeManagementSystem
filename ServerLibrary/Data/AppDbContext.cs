using BaseLibrary.Entities;
using Microsoft.EntityFrameworkCore;

namespace ServerLibrary.Data
{
    public class AppDbContext(DbContextOptions options) : DbContext(options)
    {
        public DbSet<Employee> Employees {  get; set; }
        public DbSet<GeneraleDepartement> GeneraleDepartements { get; set; }
        public DbSet<Departement> Departements { get; set; }
        public DbSet<Branch> Branches { get; set; }
        public DbSet<Town> Towns { get; set; }
        public DbSet<ApplicationUser> ApplicationUsers { get; set; }

        public DbSet<SystemRole> SystemRoles { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }

        public DbSet<RefreshTokenInfo> RefreshTokenInfos { get; set; }

    }
}
