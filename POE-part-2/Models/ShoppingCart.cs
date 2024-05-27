using System;
using System.Collections.Generic;

namespace POE_part_2.Models;

public partial class ShoppingCart
{
    public string CartId { get; set; } = Guid.NewGuid().ToString(); 

    public string UserId { get; set; } 

    public decimal TotalPrice { get; set; }

    public int TotalNumItems { get; set; }

    public string Status { get; set; } = null!;

    public TimeOnly Timestamp { get; set; }

    public virtual ICollection<CartItem> CartItems { get; set; } = new List<CartItem>();

    public virtual AspNetUser User { get; set; } 
}
