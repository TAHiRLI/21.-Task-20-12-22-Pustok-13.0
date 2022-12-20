const btns = document.getElementsByClassName("close");


for (let item of btns) {
    item.addEventListener("click", (e) => {
        e.target.parentElement.removeChild(e.target.parentElement.lastElementChild);
        e.target.parentElement.style.display = "none";
    });

}





let posterInput = document.getElementById("PosterImg");
let hoverInput = document.getElementById("HoverImg");
let hoverImgContainer = document.getElementById("hoverImages");
let posterImgContainer = document.getElementById("posterImages");



console.log(hoverInput);
let inputArray = [posterInput, hoverInput];

inputArray.forEach(input => {
         let i = 0; 
    input.addEventListener("change", ()=> {
    let file =input.files[0];
    let reader = new FileReader();

    reader.readAsDataURL(file);
    reader.onload= ()=>{
        console.log(reader.result);

        let parentDiv = document.createElement("div");
        parentDiv.classList.add("col-md-2", "position-relative",'border-1','border-dark', 'rounded');
        let iconDiv = document.createElement("div");
        iconDiv.classList.add("close");
        let icon = document.createElement("i");
        icon.classList.add("fas", 'fa-window-close', 'text-danger','d-block');
        let image = document.createElement("img");
        image.setAttribute("src", reader.result);
        image.setAttribute("width", '100%');

        i == 0 ?
           posterImgContainer.appendChild(parentDiv) :
            hoverImgContainer.appendChild(parentDiv);

       // iconDiv.appendChild(icon);
       // parentDiv.appendChild(iconDiv);
        parentDiv.appendChild(image);
        i++;
    }
})
  
})

