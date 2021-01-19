import sass

compileFile("src/assets/sass/application.scss",
            outputPath = "public/css/style.css",
            includePaths = @["src/sass/include"])

echo "Compiled to public/css/style.css"
