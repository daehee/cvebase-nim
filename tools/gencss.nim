import sass

compileFile("src/sass/application.scss",
            outputPath = "public/css/style.css",
            includePaths = @["src/sass/include"])

echo "Compiled to public/css/style.css"
