using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JwtCleanArch.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class ApplicationUserModifired : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Address",
                table: "ApplicationUsers",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Email",
                table: "ApplicationUsers",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "IdentityUserId",
                table: "ApplicationUsers",
                type: "nvarchar(450)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_ApplicationUsers_IdentityUserId",
                table: "ApplicationUsers",
                column: "IdentityUserId",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_ApplicationUsers_AspNetUsers_IdentityUserId",
                table: "ApplicationUsers",
                column: "IdentityUserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_ApplicationUsers_AspNetUsers_IdentityUserId",
                table: "ApplicationUsers");

            migrationBuilder.DropIndex(
                name: "IX_ApplicationUsers_IdentityUserId",
                table: "ApplicationUsers");

            migrationBuilder.DropColumn(
                name: "Address",
                table: "ApplicationUsers");

            migrationBuilder.DropColumn(
                name: "Email",
                table: "ApplicationUsers");

            migrationBuilder.DropColumn(
                name: "IdentityUserId",
                table: "ApplicationUsers");
        }
    }
}
