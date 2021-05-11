using System;

namespace DatingApp.API.Models
{
    public class Photo
    {
        public int Id { get; set; }
        public string Url { get; set; }
        public string Description { get; set; } 
        public DateTime DateAdd { get; set; }
        public bool IsMain { get; set; }

        //estes dois de baixo são criados para que o migration faça o cascate delete corretamente nas tabelas
        public User User { get; set; }
        public int UserId { get; set; }
    }
}