using System;
using System.Collections.Generic;

namespace POE_part_2.Models;

public partial class CartItem
{
    public string CartItemId { get; set; } = Guid.NewGuid().ToString();      

    public string CartId { get; set; }  

    public string ArtworkId { get; set; }   

    public int Quantity { get; set; }

    public decimal TotalPriceContribution { get; set; }
    // navigation properties

    public virtual ArtWork Artwork { get; set; }    

    public virtual ShoppingCart Cart { get; set; }  
}
