var edge = require('edge');

var helloWorld = edge.func({
    assemblyFile:'Pdfwork.dll'
});

var strings=['pdfs/eoir-29.pdf', 'Seth', 'Kitchen', '506 E 12 Street', '6365796535', 'sjkyv5@mst.edu', 'Rolla', '65401', 'MO', 'US', '02/10/1996', 'male', 'english']

helloWorld(strings, function (error, result) {
    if (error) throw error;
    console.log(result);
});