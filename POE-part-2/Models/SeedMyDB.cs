using Microsoft.EntityFrameworkCore;
using POE_part_2.Data;

namespace POE_part_2.Models
{
    public class SeedMyDB
    {
        public static async Task SeedData(IServiceProvider serviceProvider)
        {
            using (var scope = serviceProvider.CreateScope())
            {
                var appContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                var khumaloContext = scope.ServiceProvider.GetRequiredService<KhumaloCraftContext>();

                var identityRoles = await appContext.Roles.ToListAsync();
                var khumaloRoles = identityRoles.Select(role => new AspNetRole
                {
                    Name = role.Name,
                    Id = role.Id,
                    NormalizedName = role.NormalizedName,
                    ConcurrencyStamp = role.ConcurrencyStamp
                }).ToList();

                if (!await khumaloContext.AspNetRoles.AnyAsync())
                {
                    khumaloContext.AspNetRoles.AddRange(khumaloRoles);
                    await khumaloContext.SaveChangesAsync();
                }

                await SeedCategoryDataAsync(khumaloContext);
                await SeedCourierDataAsync(khumaloContext);
            }
        }

        private static async Task SeedCourierDataAsync(KhumaloCraftContext context)
        {
            if (!await context.Couriers.AnyAsync())
            {
                context.Couriers.AddRange(
                    new Courier { CourierId = Guid.NewGuid().ToString(), CourierName = "DefEx", CourierAddress = "Fake street 123" },
                    new Courier { CourierId = Guid.NewGuid().ToString(), CourierName = "FlyingEagle", CourierAddress = "Heaven road 123" }
                );
                await context.SaveChangesAsync();
            }
        }

        private static async Task SeedCategoryDataAsync(KhumaloCraftContext khumaloContext)
        {
            if (!await khumaloContext.Categories.AnyAsync())
            {
                khumaloContext.Categories.AddRange(
                    new Category
                    {
                        CategoryId = Guid.NewGuid().ToString(),
                        CategoryName = "Ceramic",
                        CategoryDescription = "Crafting clay into functional pottery and decorative sculptures through molding and firing."
                    },
                    new Category { CategoryId = Guid.NewGuid().ToString(), CategoryName = "WoodWorking", CategoryDescription = "Shaping and assembling wood into furniture, art pieces, and decorative objects." },
                    new Category { CategoryId = Guid.NewGuid().ToString(), CategoryName = "Metalworking", CategoryDescription = "Crafting metal into jewelry, sculptures, and tools through forging and welding." },
                    new Category { CategoryId = Guid.NewGuid().ToString(), CategoryName = "Textiles", CategoryDescription = "Creating fabrics and textile products through weaving, knitting, and embroidery." },
                    new Category { CategoryId = Guid.NewGuid().ToString(), CategoryName = "Glassblowing", CategoryDescription = "Shaping molten glass into ornaments, vases, and sculptures through blowing and molding." },
                    new Category { CategoryId = Guid.NewGuid().ToString(), CategoryName = "Leatherworking", CategoryDescription = "Crafting leather into bags, belts, and accessories through cutting and stitching." },
                    new Category { CategoryId = Guid.NewGuid().ToString(), CategoryName = "Candle Making", CategoryDescription = "Producing decorative and aromatic candles using wax and fragrances." }
                );
                await khumaloContext.SaveChangesAsync();
            }
        }
    }
}
