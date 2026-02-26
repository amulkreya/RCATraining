
router.post('/create-student', async (req, res) => {
  const { name, email, mobile, password, sessionid } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  await pool.query(
    `INSERT INTO UserInformation
     (name,email,mobile,password,role,isactive,sessionid)
     VALUES($1,$2,$3,$4,'Student',true,$5)`,
    [name,email,mobile,hashed,sessionid]
  );

  res.redirect('/admin.html');
});
