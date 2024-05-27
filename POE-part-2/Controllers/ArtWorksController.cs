using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using POE_part_2.Models;

namespace POE_part_2.Controllers
{
    public class ArtWorksController : Controller
    {
        private readonly KhumaloCraftContext _context;

        public ArtWorksController(KhumaloCraftContext context)
        {
            _context = context;
        }

        // GET: ArtWorks
        public async Task<IActionResult> Index()
        {
            var khumaloCraftContext = _context.ArtWorks.Include(a => a.Artist);
            return View(await khumaloCraftContext.ToListAsync());
        }

        // GET: ArtWorks/Details/5
        public async Task<IActionResult> Details(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var artWork = await _context.ArtWorks
                .Include(a => a.Artist)
                .FirstOrDefaultAsync(m => m.ArtWorkId == id);
            if (artWork == null)
            {
                return NotFound();
            }

            return View(artWork);
        }
        [Authorize(Roles = "Admin,Artist")]
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [Authorize(Roles = "Admin,Artist")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ArtWorkId,UserId,ProductName,Price,Picture,Availability,Quantity,QuatityThreshold,MaxQuantity")] ArtWork artWork, IFormFile imageFile)
        {
            if (ModelState.IsValid)
            {
                artWork.ArtWorkId = Guid.NewGuid().ToString();
                artWork.UserId = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (imageFile != null && imageFile.Length > 0)
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        await imageFile.CopyToAsync(memoryStream);
                        artWork.Picture = memoryStream.ToArray();
                    }

                    artWork.Quantity = artWork.MaxQuantity;
                    artWork.QuatityThreshold = (int)(artWork.MaxQuantity * 0.2);
                }

                _context.Add(artWork);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }

            return View(artWork);
        }


        [Authorize(Roles = "Admin,Artist")]
        // GET: ArtWorks/Edit/5
        public async Task<IActionResult> Edit(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var artWork = await _context.ArtWorks.FindAsync(id);
            if (artWork == null)
            {
                return NotFound();
            }

            return View(artWork);
        }

        [Authorize(Roles = "Admin,Artist")]
        // POST: ArtWorks/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string id, [Bind("ArtWorkId,UserId,ProductName,Price,Picture,Availability,Quantity,QuatityThreshold,MaxQuantity")] ArtWork artWork)
        {
            if (id != artWork.ArtWorkId)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(artWork);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!ArtWorkExists(artWork.ArtWorkId))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }

                return RedirectToAction(nameof(Index));
            }

            return View(artWork);
        }

        [Authorize(Roles = "Admin,Artist")]
        // GET: ArtWorks/Delete/5
        public async Task<IActionResult> Delete(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var artWork = await _context.ArtWorks
                .Include(a => a.Artist)
                .FirstOrDefaultAsync(m => m.ArtWorkId == id);
            if (artWork == null)
            {
                return NotFound();
            }

            return View(artWork);
        }

        [Authorize(Roles = "Admin,Artist")]
        // POST: ArtWorks/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            var artWork = await _context.ArtWorks.FindAsync(id);
            if (artWork != null)
            {
                _context.ArtWorks.Remove(artWork);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool ArtWorkExists(string id)
        {
            return _context.ArtWorks.Any(e => e.ArtWorkId == id);
        }
    }
}
