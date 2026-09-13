
document.getElementById("host").textContent = location.origin;
document.getElementById("f").addEventListener("submit", function(ev){
  ev.preventDefault();
  var v = document.getElementById("p").value.trim().replace(/^[/\s]+|[/\s]+$/g, "");
  if(!v){ document.getElementById("e").textContent = "请输入路径"; return; }
  if(/[^A-Za-z0-9._~-]/.test(v)){ document.getElementById("e").textContent = "路径只含字母、数字、-、_、.、~"; return; }
  location.href = "/" + v;
});
