using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace POE_part_2.Models
{
    public class IdentitySeed
    {
        public static async Task SeedRolesAndClaims(IServiceProvider serviceProvider)
        {
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = serviceProvider.GetRequiredService<UserManager<IdentityUser>>();

            var roles = new[] { "Admin", "Artist", "User" };
            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    await roleManager.CreateAsync(new IdentityRole(role));
                }
            }

            var adminRole = await roleManager.FindByNameAsync("Admin");
            if (adminRole != null)
            {
                var claim = new Claim("AppPermission", "ManageAppData");
                if (!(await roleManager.GetClaimsAsync(adminRole)).Any(c => c.Type == claim.Type && c.Value == claim.Value))
                {
                    await roleManager.AddClaimAsync(adminRole, claim);
                }
            }

            var adminEmail = "God@Heaven.com";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);
            if (adminUser == null)
            {
                adminUser = new IdentityUser { UserName = adminEmail, Email = adminEmail};
                var result = await userManager.CreateAsync(adminUser, "God123$");

                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, "Admin");
                }
                else
                {
                    var logger = serviceProvider.GetRequiredService<ILogger<IdentitySeed>>();
                    foreach (var error in result.Errors)
                    {
                        logger.LogError(error.Description);
                    }
                }
            }
        }
    }
}
