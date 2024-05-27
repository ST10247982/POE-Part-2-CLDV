using System;
using System.Collections.Generic;

namespace POE_part_2.Models;

public partial class ArtWork
{
    public string ArtWorkId { get; set; } 

    public string UserId { get; set; }

    public string? ProductName { get; set; } 

    public decimal Price { get; set; }

    public byte[] Picture { get; set; } 

    public string? Availability { get; set; } 

    public int Quantity { get; set; }

    public int QuatityThreshold { get; set; }

    public int MaxQuantity { get; set; }

    public virtual ICollection<CartItem> CartItems { get; set; } = new List<CartItem>();

    public virtual ICollection<Review> Reviews { get; set; } = new List<Review>();

    public virtual ICollection<TransactionProduct> TransactionProducts { get; set; } = new List<TransactionProduct>();

    public virtual AspNetUser Artist { get; set; } 
}
