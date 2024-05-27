using System;
using System.Collections.Generic;

namespace POE_part_2.Models;

public partial class Review
{
    public string ReviewId { get; set; } 

    public string UserId { get; set; } 

    public string ArtworkId { get; set; }

    public decimal? Rating { get; set; }

    public string? ReviewText { get; set; }

    public DateOnly ReviewDate { get; set; }

    public virtual ArtWork Artwork { get; set; } 

    public virtual AspNetUser User { get; set; } = null!;
}
