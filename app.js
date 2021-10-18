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
var mime = require('mime');

var passed = false; // 로그인 비활성화 기본 상태

// 사용자 함수 선언
function encryptionPW(pw) { // 비밀번호 암호화
  var encrypted = crypto.createHash('sha512').update(pw).digest('base64');
  encrypted = encrypted.substring(0, 9)
  return encrypted;
}

function now() {  // 지금 시간 추출
  var currentdate = new Date();
  var now = currentdate.toFormat('YYYY-MM-DD HH24:MI:SS');
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
    database: 'ebs',
    dateStrings: 'date'
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
var router = express.Router();
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
    // maxAge: 1000 * 60 * 2
  },
  rolling: true,
  store: new FileStore()
}));

//var loggedin = false;
var loginid = -1;

// 파일 경로 저장
var storage = multer.diskStorage({
    destination: function (req, file, cb){
        cb(null, 'files/')
    },
    filename: function (req, file, cb){
        cb(null, Date.now() + '-' + file.originalname)
    }
});

var upload = multer({
  storage: storage
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
  var sql = 'SELECT * FROM post ORDER BY date DESC';

  client.query(sql, (err, result, fields) => {
    if(err){
      logging(sql);
      logging(now() + ' : DB 오류 발생.');
      res.send("<script>alert('오류');location.href='/home';</script>");
    } else{
      res.render('home.ejs', {
        result: result
      });
      logging(now() + ' : 홈 페이지에 접속하였습니다!');
    }
  });
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
  var order = ' ORDER BY';
  var day = ' date';
  var dead = ' deadline';
  var latest = ' ASC';
  var recent = ' DESC';

  var sql = 'SELECT * FROM post WHERE date < now()';
  var searchquery = 'SELECT * FROM post WHERE date < now() AND (title LIKE ? OR content LIKE ?)';

  if(req.query.category == 'stuff'){
    searchquery = searchquery + " AND category='물품'";
    sql = sql + " AND category='물품'";
  } else if (req.query.category == 'work') {
    searchquery = searchquery + " AND category='공사'";
    sql = sql + " AND category='공사'";
  } else if (req.query.category == 'service') {
    searchquery = searchquery + " AND category='용역'";
    sql = sql + " AND category='용역'";
  } else if (req.query.category == 'foreign') {
    searchquery = searchquery + " AND category='외자'";
    sql = sql + " AND category='외자'";
  } else if (req.query.category == 'reserve') {
    searchquery = searchquery + " AND category='비축'";
    sql = sql + " AND category='비축'";
  } else if (req.query.category == 'etc') {
    searchquery = searchquery + " AND category='기타'";
    sql = sql + " AND category='기타'";
  }

  if(req.query.dead){
    searchquery = searchquery + " AND deadline > now()";
    sql = sql + " AND deadline > now()";
  }
  if(req.query.almost_dead){
    searchquery = searchquery + " AND deadline > date_add(now(), interval 7 day)";
    sql = sql + " AND deadline > date_add(now(), interval 7 day)";
  }
  if(req.query.old){
    searchquery = searchquery + " AND date > date_sub(now(), interval 3 day)";
    sql = sql + " AND date > date_sub(now(), interval 3 day)";
  }
  if(req.query.overlap){
    searchquery = searchquery + " GROUP BY title";
    sql = sql + " GROUP BY title";
  }

  if(req.query.day == 'day_recent'){
    searchquery = searchquery + order + day + recent;
    sql = sql + order + day + recent;
  } else if (req.query.day == 'dead_latest') {
    searchquery = searchquery + order + dead + recent;
    sql = sql + order + dead + recent;
  } else if (req.query.day == 'dead_recent') {
    searchquery = searchquery + order + dead + latest;
    sql = sql + order + dead + latest;
  } else if(req.query.day == 'day_latest'){
    searchquery = searchquery + order + day + latest;
    sql = sql + order + day + latest;
  } else{
    searchquery = searchquery + order + day + recent;
    sql = sql + order + day + recent;
  }

  if(req.query.searchb){
    var search = req.query.searchb;
    logging(searchquery);
    client.query(searchquery, ['%'+search+'%', '%'+search+'%'], function(err, results){
      if(err){
        logging(now() + ' : DB 오류 발생.');
        res.send("<script>alert('오류');location.href='/home';</script>");
      } else{
        res.render('posting.ejs', {
          result: results
        });
      }
    });
  } else{
    client.query(sql, (err, result, fields) => {
      if(err){
        logging(sql);
        logging(now() + ' : DB 오류 발생.');
        res.send("<script>alert('오류');location.href='/home';</script>");
      } else{
        res.render('posting.ejs', {
          result: result
        });
        logging(now() + ' : 입찰공고 페이지에 접속하였습니다.');
      }
    });
  }
});

app.get('/post/:id', function(req, res, next){
  var id = req.params.id;

  var sqlcount = 'UPDATE post SET count=count+1 where id=?';
  client.query(sqlcount, [id], function(err, result){
    if(err){
      logging(now() + ' : 글 렌더링 오류!');
      res.send("<script>alert('오류');location.href='/home';</script>");
    }else{
      var sql = 'SELECT id, auth, date, title, content, category, count, file, deadline from post where id=?';
      client.query(sql, [id], function(err, row){
        f = row[0].file;
        fi = f.split('/');
        file = fi[2];
        res.render('post', {title: '글 상세', row: row[0], file: file});
      });
    }
  });
});

// 파일 다운로드
app.get('/download/:file_name', function(req, res, next) {
  var upload_folder = 'files/';
  var file = upload_folder + req.params.file_name; // ex) /upload/files/sample.txt

  try {
    if (fs.existsSync(file)) { // 파일이 존재하는지 체크
      logging('1');
      var filename = path.basename(file); // 파일 경로에서 파일명(확장자포함)만 추출
      var mimetype = mime.lookup(file); // 파일의 타입(형식)을 가져옴

      res.setHeader('Content-disposition', 'attachment; filename=' + filename); // 다운받아질 파일명 설정
      res.setHeader('Content-type', mimetype); // 파일 형식 지정
      logging('2');

      var filestream = fs.createReadStream(file);
      logging('3');
      filestream.pipe(res);
    } else {
      res.send('해당 파일이 없습니다.');
      return;
    }
  } catch (e) { // 에러 발생시
    console.log(e);
    res.send('파일을 다운로드하는 중에 에러가 발생하였습니다.');
    return;
  }
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
    var sql = 'SELECT * FROM post WHERE auth=? ORDER BY date DESC';
    client.query(sql, [req.session.name], function(err, result){
      res.render('mypage.ejs',{
        user_id: req.session.userid,
        name: req.session.name,
        provider: req.session.prov,
        created_at: req.session.date,
        result: result
      });
    });
    logging(now() + ' : 마이페이지에 접속하였습니다.');
  } else{
    logging(now() + ' : 허가받지 않은 사용자가 마이페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

app.get('/delete/:id', function(req, res, next){
  var id = req.params.id;

  var sql = 'DELETE FROM post WHERE id=?';
  client.query(sql, [id], function(err, row){
    logging(now() + ' : '+ id + '번 째 공고를 삭제하였습니다.');
    res.send("<script>alert('공고를 삭제하였습니다!');location.href='/mypage';</script>");
  });
});

app.get('/edit/:id', function(req, res, next){
  var id = req.params.id;

  var sql = 'SELECT id, auth, date, title, content, category, count, file, deadline from post where id=?';
  client.query(sql, [id], function(err, row){
    f = row[0].file;
    fi = f.split('/');
    file = fi[2];
    res.render('edit', {
      row: row[0],
      file: file
    });
  });
});

app.post('/edit/:id', upload.single('file'), (req, res) => {
  logging('수정 페이지 접속');
  var id = req.body.id;
  var title = req.body.title;
  var content = req.body.content;
  var category = req.body.category;
  var name = req.file.filename;
  var file = `/files/${name}`;
  var deadline = req.body.date + ' ' + req.body.time+':00';

  client.query('UPDATE post SET date=?, title=?, content=?, category=?, file=?, deadline=? WHERE id=?', [now(), title, content, category, file, deadline, id], function(err, result){
    if(err){
      logging('오류');
    } else{
      logging(now() + ' : 글이 수정되었습니다.');
      res.send("<script>location.href='/mypage';</script>");
    }
  });
});

//로그인 요청
app.get('/plzlogin', function(req, res, next){
  res.render('plzlogin.ejs');
  logging(now() + ' : 로그인 하지 않은 사용자가 접속을 시도하였습니다..');
});

// 개찰 결과 등록 페이지
app.get('/opening', function(req, res, next){
  var order = ' ORDER BY';
  var day = ' date';
  var dead = ' deadline';
  var latest = ' ASC';
  var recent = ' DESC';

  var sql = 'SELECT * FROM post WHERE auth=? AND deadline<?';

  if(req.query.day == 'day_recent'){
    sql = sql + order + day + recent;
  } else if (req.query.day == 'dead_recent') {
    sql = sql + order + dead + recent;
  } else if (req.query.day == 'dead_latest') {
    sql = sql + order + dead + latest;
  } else if(req.query.day == 'day_latest'){
    sql = sql + order + day + latest;
  } else{
    sql = sql + order + day + recent;
  }

  if(req.session.loggedin == true){
    client.query(sql, [req.session.name, now()],function(err, result){
      if(err){
        logging(now() + ' : DB 오류 발생.');
        res.send("<script>alert('오류');location.href='/home';</script>");
      } else{
        logging(sql);
        res.render('opening.ejs', {
          result: result
        });
        logging(now() + ' : 개찰 결과 등록 페이지에 접속하였습니다.');
      }
    });
  } else{
    logging(now() + ' : 허가받지 않은 사용자가 개찰 결과 등록 페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

app.get('/open/:id', function(req, res, next){
  var id = req.params.id;
  logging(id);

  if(req.session.loggedin == true){
    var sql = 'SELECT * FROM bidding WHERE post_id=?';
    client.query(sql, [id], function(err, result){
      if(result.length != 0){
        var sqlpost = 'SELECT title FROM post WHERE id=?';
        client.query(sqlpost, [id], function(err, data){
          var f = result[0].bid_file;
          fi = f.split('/');
          file = fi[2];

          var t = JSON.stringify(data[0]);
          var title = t.substring(10, t.length-2);

          var already = 0;

          for(var i = 0; i < result.length; i++){
            if(result[i].bid_select == 1){
              already++;
            }
          }
          if(already > 0){
            res.send("<script>alert('이미 개찰된 공고입니다! 개찰 결과를 등록할 수 없습니다.');location.href='/opening';</script>");
            logging(now() + ' : 이미 개찰된 공고입니다.');
          } else{
            res.render('open.ejs',{
              result: result,
              title: title+'의',
              file: file,
              id: id
            });
          }
        });
      } else {
        res.render('notopen.ejs');
        logging(now() + ' : 아직 입찰이 없습니다.');
      }
    });
    logging(now() + ' : 입찰 현황 페이지에 접속하였습니다.');

  } else{
    logging(now() + ' : 허가받지 않은 사용자가 개찰 결과 등록 페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

app.get('/bidselect/:post_id/:id', function(req, res, next){
  var bid_id = req.params.id;
  var post_id = req.params.post_id;

  var sql = 'SELECT bid_select FROM bidding WHERE post_id=?';
  client.query(sql, [post_id], function(err, result){
    if(err){
      logging('오류1');
    } else{
      var sqlbid = 'UPDATE bidding SET bid_select=1 WHERE id=?';
      client.query(sqlbid, [bid_id], function(err, data){
        if(err){
          logging('오류2');
        } else {
          res.send("<script>alert('낙찰하였습니다! 개찰 결과에 표시됩니다.');location.href='/opening';</script>");
          logging(now() + ' : ' + bid_id + '번째 입찰이 선택되었습니다. 개찰 결과에 표시됩니다.');
        }
      });
    }
  });
});

// 개찰 결과 열람 페이지
app.get('/bidOpen', function(req, res, next){
  if(req.session.loggedin == true){
    var sql = 'SELECT * FROM bidding WHERE auth_id=? ORDER BY bid_time DESC';
    client.query(sql, [req.session.idnum], function(err, result){
      if(result){
        var f = result[0].bid_file;
        fi = f.split('/');
        file = fi[2];

        res.render('bidOpen.ejs',{
          result: result,
          file: file
        });
      }else{
        logging(now() + ' : 아직 참여한 입찰이 없습니다.');
        res.send("<script>alert('아직 참여한 입찰이 없습니다.');location.href='/posting';</script>");
      }
    });
    logging(now() + ' : 개찰결과 열람 페이지에 접속하였습니다.');
  } else{
    logging(now() + ' : 허가받지 않은 사용자가 개찰 열람 페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

app.get('/bidOpen/:post_id/:id', function(req, res, next){
  var post_id = req.params.post_id;
  var id = req.params.id;

  if(req.session.loggedin == true){
    var sql = 'SELECT * FROM post WHERE id=?';
    client.query(sql, [post_id], function(err, result){
      if(err){
        logging('오류1');
      } else{
        var sqlbid = 'SELECT * FROM bidding WHERE id=?';
        client.query(sqlbid, [id], function(err, results){
          if(err){
            logging('오류2');
          } else{
            var sqlselect = 'SELECT * FROM bidding WHERE post_id=?';
            client.query(sqlselect, [post_id], function(err, data){
              if(err){
                logging('오류3');
              } else{
                var select = 0;

                for(var i = 0; i < data.length; i++){
                  if(data[i].bid_select == 1){
                    select++;
                  }
                }

                if(select > 0){
                  var f = result[0].file;
                  fi = f.split('/');
                  file = fi[2];

                  logging(now() + ' : 개찰결과 확인 페이지에 접속하였습니다.');
                  res.render('bidOpenpage.ejs',{
                    result: result[0],
                    results: results[0],
                    file: file
                  });
                } else {
                  logging(now() + ' : 아직 개찰이 완료되지 않았습니다.');
                  res.send("<script>alert('아직 개찰이 완료되지 않았습니다.');location.href='/bidOpen';</script>");
                }
              }
            });
          }
        });
      }
    });
  } else{
    logging(now() + ' : 허가받지 않은 사용자가 개찰 확인 페이지에 접속하였습니다.');
    res.send("<script>alert('로그인이 필요합니다!');location.href='/login';</script>");
  }
});

app.get('/bid/:id', function(req, res, next){
  var id = req.params.id;

  var sql = 'SELECT id, auth, date, title, content, category, count, file, deadline from post where id=?';
  client.query(sql, [id], function(err, row){
    logging(row[0].deadline);
    if(row[0].deadline > now()){
      if(row[0].auth == req.session.name){
        logging(now() + ' : 자신이 올린 공고에 입찰을 신청하였습니다..');
        res.send("<script>alert('자신이 올린 공고에는 입찰 신청할 수 없습니다.');location.href='/posting';</script>");
      } else{
        f = row[0].file;
        fi = f.split('/');
        file = fi[2];
        res.render('bid', {
          row: row[0],
          file: file
        });
      }
    }else{
      logging(now() + ' : 입찰이 마감된 공고입니다.');
      res.send("<script>alert('입찰이 마감된 공고입니다.');location.href='/posting';</script>");
    };
  });
});

app.get('/noticePosts', function(req, res, next){
  res.render('noticePosts.ejs');
});

app.get('/A1', function(req, res, next){
  res.render('A1.ejs');
});




// post

// 로그인 페이지
app.post('/login', function(request, response){
  var id = request.body.id;
  var pd = request.body.pw;

  // 사용자 id가 존재하는지 확인
  var sql = 'SELECT * FROM user WHERE user_id = ?';
  client.query(sql, [id], (err, data) => {

    if (err) {
      logging(now() + ' : 로그인 오류 발생.');
      response.send("<script>alert('오류');location.href='/login';</script>");
    }

    // 동일한 id가 있는지 확인
    else if (data.length === 0) {
      logging(now() + ' : ID가 다릅니다. 로그인 실패!');
      response.send("<script>alert('ID 혹은 암호가 다릅니다!');location.href='/login';</script>");
    }else{
      var idnum = data[0].id;
      var id = data[0].user_id;
      var name = data[0].name;
      var prov = data[0].provider;
      var date = data[0].created_at;

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
                request.session.idnum = idnum;
                request.session.userid = id;
                request.session.name = name;
                request.session.prov = prov;
                request.session.date = date;
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
  var p1 = request.body.txtMobile1;
  var p2 = request.body.txtMobile2;
  var p3 = request.body.txtMobile3;
  var phone = p1 +'-'+ p2 +'-'+ p3;
  logging(phone);
  var time = now();

  // user테이블에 해당 user_ID가 이미 있는지 확인하는 쿼리
  var idcheck = 'SELECT * FROM user WHERE user_id = ?';
  var namecheck = 'SELECT * FROM user WHERE name = ?';

  // 입력이 다 되어있는지 확인
  if(!id || !pd || !pwre || !name || !provider || !ch || !phone){
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
      } else if(results.length >= 1){ // 이미 같은 id로 회원이 존재한다면
        logging(now() + ' : 중복 ID로 회원가입 시도하여 실패!');
        response.send("<script>alert('이미 같은 ID가 존재합니다!');location.href='/signup';</script>");
      } else { // 회원가입 시작
        client.query(namecheck, [name], (err, data, fields) => {
          if(err){
            logging(now() + ' : 회원가입 DB 오류! 3' + err);
            response.send("<script>alert('오류');location.href='/signup';</script>");
          } else if(data.length >= 1){
            logging(now() + ' : 중복 이름으로 회원가입 시도하여 실패!');
            response.send("<script>alert('이미 같은 이름이 존재합니다!');location.href='/signup';</script>");
          } else{
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
            signupsql = 'INSERT INTO user (user_id, password, name, provider, created_at, phone_num) VALUES (?, ?, ?, ?, ?, ?)';
            client.query(signupsql, [id, encryption, name, provider, time, phone], function(err, result, fields){
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
  }
});

// 공고 작성
app.post('/postW/write', upload.single('file'), (req, res)=>{

  var title = req.body.title;
  var category = req.body.category;
  var content = req.body.content;
  var file = `/files/${req.file.filename}`;
  var deadline = req.body.date + ' ' + req.body.time+':00';

  if(deadline < now()){
    logging(now() + ' : 날짜 입력 오류!');
    res.send("<script>alert('잘못된 개찰일 설정입니다.');location.href='/postW';</script>");
  }else{
    var datas = [req.session.name, now(), title, content, category, file, deadline];
    var sql = 'INSERT INTO post(auth, date, title, content, category, count, file, deadline) VALUES(?, ?, ?, ?, ?, 0, ?, ?)';
    client.query(sql, datas, function(err, result){
      if(err){
        logging(now() + ' : 공고 작성 DB 오류!');
        res.send("<script>alert('오류');location.href='/postW';</script>");
      } else{
        res.redirect('/posting');
      }
    });
  }
});

// 입찰 신청 작성
app.post('/bid/:id', upload.single('bid_file'), (req, res)=>{
  var post_id = req.body.id;
  var auth_id = req.session.idnum;
  logging(post_id);
  logging(auth_id);

  var bid_firm = req.body.bid_firm;
  var bid_ceo = req.body.bid_ceo;
  var bid_price = req.body.bid_price;
  var bid_etc = req.body.bid_etc;
  var bid_file = `/files/${req.file.filename}`;

  var datas = [post_id, auth_id, bid_firm, bid_ceo, bid_price, bid_file, now(), bid_etc];
  var sql = 'INSERT INTO bidding(post_id, auth_id, bid_firm, bid_ceo, bid_price, bid_file, bid_time, bid_etc) VALUES(?, ?, ?, ?, ?, ?, ?, ?)';
  client.query(sql, datas, function(err, result){
    logging('sql '+sql);
    logging('datas '+datas);
    logging('result '+result);
    if(err){
      logging(now() + ' : 입찰 신청 DB 오류!');
      res.send("<script>alert('오류');location.href='/posting';</script>");
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
