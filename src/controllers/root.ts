export { root };

const root = (ctx: any) => {
  console.log("Handler: /");
  ctx.render("./template/index.ejs");
};
