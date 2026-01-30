using JwtCleanArch.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace JwtCleanArch.Infrastructure.Data.Configuration
{
    public class ApplicationUserConfiguration : IEntityTypeConfiguration<ApplicationUser>
    {
        public void Configure(EntityTypeBuilder<ApplicationUser> builder)
        {
            builder.HasKey(x => x.Id);
            builder.Property(x => x.FullName).IsRequired();
            builder.Property(x => x.Email).IsRequired();
            builder.HasIndex(x => x.IdentityUserId).IsUnique();

            builder.HasOne<Microsoft.AspNetCore.Identity.IdentityUser>()
                .WithMany()
                .HasForeignKey(x => x.IdentityUserId)
                .OnDelete(DeleteBehavior.Cascade);

        }
    }
}
