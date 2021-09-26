// 외부 모듈
var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var bodyParser = require('body-parser');
var crypto = require('crypto');
var newDate = require('date-utils');
var session = require('express-session');
//var MySQLStore = require('express-mysql-session')(session);
var FileStore = require('session-file-store')(session);
var cors = require('cors');
var logger = require('morgan');
var fs = require('fs');
var mysql = require('mysql');
var multer = require('multer');
var path = require('path');
var static = require('serve-static');

var passed = false; // 로그인 비활성화 기본 상태

// 사용자 함수 선언
function encryptionPW(pw) { // 비밀번호 암호화
  var encrypted = crypto.createHash('sha512').update(pw).digest('base64');
  encrypted = encrypted.substring(0, 9)
  return encrypted;
}

function now() {  // 지금 시간 추출
  var currentdate = new Date();
  var now = currentdate.getFullYear() + "-"
    + Number(currentdate.getMonth() + 1) + "-"
    + currentdate.getDate() + " "
    + currentdate.getHours() + ":"
    + currentdate.getMinutes() + ":"
    + currentdate.getSeconds();
  return now;
}

function logging(logstr){
  fs.appendFile('app.log', logstr + '\n', 'UTF8', function(err){
    if(err) throw err;
    console.log(logstr);
  });
}

// MySQL 데이터베이스 구현
try{
  var client = mysql.createConnection({
    host: 'localhost',
    port: 3306,
    user: 'root',
    password: '123456',
    database: 'ebs'
  });
} catch(e){
  console.log(e.name);
  console.log(e.message);
}
client.connect((err) => {
  if(err) {
    throw err;
  }else{
  logging('DBMS Connected !!');
}
  // user/post 테이블 없으면 생성 코드 차후 추가
});

// 서버 생성
var app = express();
// 서버 환셩 설정
app.settings.env = 'production';

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs'); // ejs 사용
app.engine('html', require('ejs').renderFile);

// 미들웨어 설정
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '/')));
app.use('/files', static(path.join(__dirname, 'files')));
app.use(bodyParser.urlencoded({extended: false}));
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(session({
  key: 'loginData',
  secret: 'secret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    expires: 60 * 60 * 24
  },
  store: new FileStore()
}));

//var loggedin = false;
var loginid = -1;

// 파일 경로 저장
var storage = multer.diskStorage({
    destination: function (req, file, callback){
        callback(null, 'files/')
    },
    filename: function (req, file, callback){
        callback(null, file.originalname + '-' + Date.now())
    }
});

var upload = multer({
  storage: storage
});

app.get('/test', function(req, res, next){
  res.render('test.ejs');
});



//app.use('/', indexRouter);
//app.use('/users', usersRouter);

// 라우팅



// 홈페이지
app.get('/', function(req, res, next){
  res.redirect('/home');
  logging(now() + ' : 홈 페이지에 접속하였습니다!');
});

app.get('/home', function(req, res, next){
  res.render('home.ejs');
  logging(now() + ' : 홈 페이지에 접속하였습니다!');
});

// 공지사항
app.get('/notice', function(req, res, next){
  res.render('notice.ejs');
  logging(now() + ' : 공지사항 페이지에 접속하였습니다.');
});

// Q&A
app.get('/Q&A', function(req, res, next){
  res.render('Q&A.ejs');
  logging(now() + ' : 질문 페이지에 접속하였습니다.');
});

// 입찰 공고
app.get('/posting', function(req, res, next){
  res.render('posting.ejs');
  logging(now() + ' : 입찰공고 페이지에 접속하였습니다.');
});

// 공고 작성
app.get('/postW', function(req, res, next){
  if(req.session.loggedin == true){
    res.render('postW.ejs');
    logging(now() + ' : 공고 작성 페이지에 접속하였습니다.');
  } else{
    logging(now() + ' : 허가받지 않은 사용자가 공고 작성 페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

// 개찰 결과
app.get('/bidOpen', function(req, res, next){
  if(req.session.loggedin == true){
    res.render('bidOpen.ejs');
    logging(now() + ' : 개찰 결과 페이지에 접속하였습니다.');
  } else{
    logging(now() + ' : 허가받지 않은 사용자가 개찰 결과 페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

// 로그아웃
app.get('/logout', function(request, response, next){
  request.session.loggedin = false;
  loginid = -1;
  logging(now() + ' : 로그아웃!');
  response.send("<script>alert('성공적으로 로그아웃 되었습니다.');location.href='/home';</script>");
});

// 로그인
app.get('/login', function(req, res, next){
  res.render('login.ejs');
  logging(now() +  ' : ' +req.session.loggedin);
  logging(now() + ' : 로그인 페이지에 접속하였습니다.');
});

// 회원가입
app.get('/signUp', function(req, res, next){
  res.render('signUp.ejs');
  logging(now() + ' : 회원가입 페이지에 접속하였습니다.');
});

// 마이페이지
app.get('/mypage', function(req, res, next){
  logging(now() + ' : ' + req.session.loggedin);
  if(req.session.loggedin == true){
    //for (variable in loginid){
    //  var logvalue = JSON.stringify(loginid[variable]);
    //}
    //var logg = logvalue.substring(6, logvalue.length-1);
    //logging(logg);
    //var sql = 'SELECT * FROM user';
    //client.query(sql, function (err, results, fields) {
      //if(err){
        //logging(now() + ' : 데이터베이스 발생.');
        //response.send("<script>alert('데이터베이스 오류');location.href='/login';</script>");
      //} else{
        //for(let i = 0; i < results.length; i++){
          //if(results[i].id == logg){
            //var user_id = results[i].user_id;
            //var name = results[i].name;
            //var provider = results[i].provider;
            //var created_at = results[i].created_at;
          //}
          //if(provider == 1){
            //provider = '공급자';
          //}else{
            //provider = '구매자';
          //}
          res.render('mypage.ejs',{
            user_id: req.session.userid,
            name: req.session.name,
            provider: req.session.prov,
            created_at: req.session.date
          });


        //res.render('mypage.ejs',{
          //user_id: user_id,
          //name: name,
          //provider: provider,
          //created_at: created_at
        //});
        logging(now() + ' : 마이페이지에 접속하였습니다.');

  } else{
    logging(now() + ' : 허가받지 않은 사용자가 마이페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

//로그인 요청
app.get('/plzlogin', function(req, res, next){
  res.render('plzlogin.ejs');
  logging(now() + ' : 로그인 하지 않은 사용자가 접속을 시도하였습니다..');
});

// post

// 로그인 페이지
app.post('/login', function(request, response){
  var id = request.body.id;
  var pd = request.body.pw;

  // 사용자 id가 존재하는지 확인
  var sql = 'SELECT * FROM user WHERE user_id = ?';
  client.query(sql, [id], (err, data) => {
    var id = data[0].user_id;
    logging('1 '+data[0].user_id);
    logging('2 '+id);
    var name = data[0].name;
    var prov = data[0].provider;
    var date = data[0].created_at;
    if (err) {
      logging(now() + ' : 로그인 오류 발생.');
      response.send("<script>alert('오류');location.href='/login';</script>");
    }

    // 동일한 id가 있는지 확인
    else if (data.length === 0) {
      logging(now() + ' : ID가 다릅니다. 로그인 실패!');
      response.send("<script>alert('ID 혹은 암호가 다릅니다!');location.href='/login';</script>");
    }else{

          // 패스워드 암호화
          var encryption = encryptionPW(pd)
          // var encryption = pd
          // 패스워드 일치 여부 확인
          sql = 'SELECT STRCMP(?, ?) AS COMPARE';
          var pwCompare = [encryption, data[0].password]
          client.query(sql, pwCompare, function (err, result, fields) {
            if (err) {
              logging(now() + ' : 로그인 오류 발생.');
              response.send("<script>alert('오류');location.href='/login';</script>");
            }

            // 패스워드가 불일치 한다면 실패
            else if (result[0].COMPARE !== 0) {
              logging(now() + ' : 암호가 다릅니다. 로그인 실패!');
              response.send("<script>alert('ID 혹은 암호가 다릅니다!');location.href='/login';</script>");
            } else{
              // 패스워드 일치 성공 시 세션에 로그인 성공 저장
                logging(now() + ' : 로그인 하였습니다!');
                request.session.loggedin = true;
                request.session.userid = id;
                request.session.name = name;
                request.session.prov = prov;
                request.session.date = date;
                logging('3 '+id);
                logging('4 '+request.session.userid);
                response.send("<script>alert('로그인 하였습니다!');location.href='/home';</script>");
              }
            });
          }
        });
  });

// 회원가입
app.post('/signup', function(request, response){
  var id = request.body.id;
  var pd = request.body.pw;
  var pwre = request.body.pwre;
  var name = request.body.name;
  var provider = request.body.provider;
  var ch = request.body.ch;
  var time = now();
  logging(provider);

  // user테이블에 해당 user_ID가 이미 있는지 확인하는 쿼리
  var idcheck = 'SELECT * FROM user WHERE user_id = ?';

  // 입력이 다 되어있는지 확인
  if(!id || !pd || !pwre || !name || !provider || !ch){
    logging(provider);
    logging(now() + ' : 데이터 입력 값 부족으로 회원가입 실패!');
    response.send("<script>alert('값을 전부 입력해주세요.');location.href='/signup';</script>");
  } else if (pd != pwre) { // 암호와 암호 확인이 같은지 확인
    logging(now() + ' : 비밀번호 확인이 틀려 회원가입 실패!');
    response.send("<script>alert('비밀번호와 비밀번호 확인이 다릅니다.');location.href='/signup';</script>");
  } else { // 위 다 만족하면 DB 확인 진행
    client.query(idcheck, [id], (err, results, fields) => {
      if(err){
        logging(now() + ' : 회원가입 DB 오류! 1' + err);
        response.send("<script>alert('오류');location.href='/signup';</script>");
      } else if(results.length === 1){ // 이미 같은 id로 회원이 존재한다면
        logging(now() + ' : 중복 ID로 회원가입 시도하여 실패!');
        response.send("<script>alert('이미 같은 ID가 존재합니다!');location.href='/signup';</script>");
      } else { // 회원가입 시작
        if (provider == "buyer") {  // 체크에 따라 구매자/공급자
          provider = 0;
          logging(provider);
        } else{
          provider = 1;
          logging(provider);
        }
        // 보안을 위해 패스워드 암호화
        var encryption = encryptionPW(pd)
        // 아이디와 암호화 한 패스워드를 DB에 저장
        signupsql = 'INSERT INTO user (user_id, password, name, provider, created_at) VALUES (?, ?, ?, ?, ?)';
        client.query(signupsql, [id, encryption, name, provider, time], function(err, result, fields){
          if (err){
            logging(now() + ' : 회원가입 DB 오류! 2');
            response.send("<script>alert('오류');location.href='/signup';</script>");
          } else{
            logging(now() + ' : 회원가입 성공!');
            response.send("<script>alert('회원가입에 성공하였습니다! 로그인해주세요.');location.href='/login';</script>");
          }
        });
      }
    });
  }
});

app.post('/test', upload.single('file'), (req, res)=>{
    var file = `/files/${req.file.filename}`;

    var datas = [file];
    var sql = 'INSERT INTO test(file) VALUES(?)';
    client.query(sql, datas, function(err, result){
      if(err){
        logging(now() + ' : 공고 작성 DB 오류!');
      } else{
        res.redirect('/');
      }
    });

});

// 공고 작성
app.post('/postW/write', upload.single('file'), (req, res)=>{

  var title = req.body.title;
  var category = req.body.category;
  var content = req.body.content;
  var file = `/files/${req.file.filename}`;

  var datas = [req.session.name, now(), title, content, category, file];
  var sql = 'INSERT INTO post(auth, date, title, content, category, count, file) VALUES(?, ?, ?, ?, ?, 0, ?)';
  client.query(sql, datas, function(err, result){
    if(err){
      logging(now() + ' : 공고 작성 DB 오류!');
      res.send("<script>alert('오류');location.href='/postW';</script>");
    } else{
      res.redirect('/posting');
    }
  });
});




// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error',{
    message: err.message,
    error: {}
  });
});



var http = require('http').Server(app);

// 서버 동작
http.listen(80, function(){
  console.log('server Running!! >> http://localhost:80');
});

//client.end();

module.exports = app;
