use dyn_fmt::AsStrFormatExt;
use reqwest::ClientBuilder;
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use tracing_subscriber::fmt::format::FmtSpan;
use warp::{Filter, Rejection, Reply};
use envconfig::Envconfig;

const DATETIME_FORMAT: &str = "%Y%m%dT%H%M%S,00%#z";

const LOGIN_URL: &str = "names.nsf?Login";
const CALENDAR_URL: &str = "mail/{}.nsf/($Calendar)?ReadViewEntries&Count=-1&KeyType=time";
// StartKey
// UntilKey

#[derive(Envconfig, Clone)]
struct Config {
    #[envconfig(from = "NOTES_USERNAME")]
    pub notes_username: String,

    #[envconfig(from = "NOTES_PASSWORD")]
    pub notes_password: String,
    
    #[envconfig(from = "NOTES_HOST")]
    pub notes_host: String,

    #[envconfig(from = "PORT", default = "3000")]
    pub port: u16,

    #[envconfig(from = "HOST", default = "0.0.0.0")]
    pub host: String,
}

async fn login(client: &reqwest::Client, host: &str, username: &str, password: &str) -> anyhow::Result<()> {
    let mut params = HashMap::new();
    params.insert("Username", username);
    params.insert("Password", password);
    let target = format!("/{}", CALENDAR_URL.format(&[username]));
    //let target = format!("https://{}{}", host, &target.as_str());
    params.insert("RedirectTo", &target.as_str());
    let response = client
        .post(format!("https://{}/{}", host, LOGIN_URL))
        .form(&params)
        .send()
        .await;

    let logged_in = response?.status() == 302; // redirecting to target ressource
    if logged_in {
        Ok(())
    } else {
        anyhow::bail!("Invalid credentials!")
    }
}

async fn load_calendar(
    client: &reqwest::Client,
    host: &str,
    username: &str,
    days_back: i64,
    days_ahead: i64,
) -> anyhow::Result<String> {
    let start =
        (chrono::Utc::now() + chrono::Duration::days(days_back)).format("%Y%m%dT000001,00Z");
    let end = (chrono::Utc::now() + chrono::Duration::days(days_ahead)).format("%Y%m%dT000001,00Z");
    let target = CALENDAR_URL.format(&[username]);
    let target = format!(
        "https://{}/{}&StartKey={}&UntilKey={}",
        host,
        &target.as_str(),
        start,
        end
    );
    let response = client.get(target).send().await?;
    let text = response.text().await?;
    let logged_in = text.contains("viewentries");
    if logged_in {
        Ok(text)
    } else {
        anyhow::bail!("Not logged in perhaps?")
    }
}

#[derive(Debug)]
struct CustomReject(anyhow::Error);

impl warp::reject::Reject for CustomReject {}

pub(crate) fn custom_reject(error: impl Into<anyhow::Error>) -> warp::Rejection {
    warp::reject::custom(CustomReject(error.into()))
}

async fn handler(
    calendar_user: String,
    client: Arc<reqwest::Client>,
    config: Config,
    params: HashMap<String, String>,
) -> anyhow::Result<impl Reply, Rejection> {
    let days_back = params
        .get("startDays")
        .and_then(|x| x.parse().ok())
        .unwrap_or(-14);
    let days_ahead = params
        .get("endDays")
        .and_then(|x| x.parse().ok())
        .unwrap_or(31);
    let filter_invites = params
        .get("filterInvites")
        .and_then(|x| x.parse().ok())
        .unwrap_or(true);
    let calendar_str = load_calendar(&client, &config.notes_host, &calendar_user, days_back, days_ahead).await;
    if let Ok(calendar_str) = calendar_str {
        tracing::info!("Got calendar for {}", calendar_user);
        Ok(parse_calendar(&calendar_str, filter_invites)
            .map_err(custom_reject)?
            .to_string())
    } else {
        tracing::info!("Logging in again");
        login(&client, &config.notes_host, &config.notes_username, &config.notes_password)
            .await
            .map_err(custom_reject)?;
        tracing::info!("Logged in, loading calendar");
        Ok(parse_calendar(
            &load_calendar(&client, &config.notes_host, &calendar_user, days_back, days_ahead)
                .await
                .map_err(custom_reject)?,
            filter_invites,
        )
        .map_err(custom_reject)?
        .to_string())
    }
}

fn with_client(
    client: Arc<reqwest::Client>,
) -> impl Filter<Extract = (Arc<reqwest::Client>,), Error = Infallible> + Clone {
    warp::any().map(move || client.clone())
}

fn with_config(
    config: Config
) -> impl Filter<Extract = (Config,), Error = Infallible> + Clone {
    warp::any().map(move || config.clone())
}

#[tokio::main]
async fn main() {
    let filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| "notes2ics=debug,tracing=info,warp=debug".to_owned());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let config = Config::init_from_env().unwrap();

    let client = ClientBuilder::new()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let client = Arc::new(client);
    let get_calendar_route = warp::path!("calendar" / String)
        .and(with_client(client))
        .and(with_config(config.clone()))
        .and(warp::query::<HashMap<String, String>>())
        .and_then(handler);
    warp::serve(
        warp::get()
            .and(get_calendar_route)
            .with(warp::trace::request()),
    )
    .run((config.host.parse::<std::net::Ipv4Addr>().unwrap(), config.port))
    .await
}

#[derive(Deserialize, Debug)]
struct CalendarDocument {
    #[serde(rename = "@timestamp")]
    _timestamp: String,
    #[serde(rename = "$value", default)]
    viewentries: Vec<ViewEntry>,
}

#[derive(Deserialize, Debug)]
struct ViewEntry {
    #[serde(rename = "$value", default)]
    entry_datas: Vec<EntryData>,
    #[serde(rename = "@unid", default)]
    uid: String,
}

#[derive(Deserialize, Debug)]
struct EntryData {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "$value")]
    data: DataList,
}

#[derive(Deserialize, Debug)]
enum DataList {
    #[serde(rename = "datetimelist")]
    DateTimeList {
        #[serde(rename = "$value")]
        datetimes: Vec<DataList>,
    },
    #[serde(rename = "numberlist")]
    NumberList {
        #[serde(rename = "$value")]
        _number: Vec<DataList>,
    },
    #[serde(rename = "textlist")]
    TextList {
        #[serde(rename = "$value")]
        texts: Vec<DataList>,
    },
    #[serde(rename = "datetime")]
    DateTime(String),
    #[serde(rename = "number")]
    Number(i32),
    #[serde(rename = "text")]
    Text(String),
    #[serde(rename = "$text")]
    Other(String),
}

impl DataList {
    fn try_first_text(&self, skip: usize) -> anyhow::Result<String> {
        Ok(match self {
            Self::Text(t) if skip == 0 => t.to_string(),
            Self::TextList { texts } => texts
                .iter()
                .skip(skip)
                .next()
                .ok_or(anyhow::anyhow!("empty"))?
                .try_first_text(0)?,
            _ => anyhow::bail!("Wrong format"),
        })
    }

    fn try_first_datetime(&self, skip: usize) -> anyhow::Result<String> {
        Ok(match self {
            Self::DateTime(v) if skip == 0 => v.to_string(),
            Self::DateTimeList { datetimes } => datetimes
                .iter()
                .skip(skip)
                .next()
                .ok_or(anyhow::anyhow!("empty"))?
                .try_first_datetime(0)?,
            _ => anyhow::bail!("Wrong format"),
        })
    }
}

fn parse_calendar(text: &str, filter_invites: bool) -> anyhow::Result<icalendar::Calendar> {
    let doc: CalendarDocument = quick_xml::de::from_str(text)?;

    let mut calendar = icalendar::Calendar::default();

    for view_entry in doc.viewentries {
        let name = view_entry
            .entry_datas
            .iter()
            .filter(|x| x.name == "$147")
            .next()
            .ok_or(anyhow::anyhow!("No summary"))
            .and_then(|x| x.data.try_first_text(0));
        let location = view_entry
            .entry_datas
            .iter()
            .filter(|x| x.name == "$147")
            .next()
            .ok_or(anyhow::anyhow!("No summary"))
            .and_then(|x| x.data.try_first_text(1));
        let start = view_entry
            .entry_datas
            .iter()
            .filter(|x| x.name == "$144")
            .next()
            .ok_or(anyhow::anyhow!("No Start"))
            .and_then(|x| x.data.try_first_datetime(0));
        let end = view_entry
            .entry_datas
            .iter()
            .filter(|x| x.name == "$146")
            .next()
            .ok_or(anyhow::anyhow!("No End"))
            .and_then(|x| x.data.try_first_datetime(0));
        let day = view_entry
            .entry_datas
            .iter().filter(|x| x.name == "$134")
            .next()
            .ok_or(anyhow::anyhow!("No Day"))
            .and_then(|x| x.data.try_first_datetime(0));

        use icalendar::Component;
        use icalendar::EventLike;
        let entry: anyhow::Result<icalendar::Event> = (|| {
            let day = day?;
            let mut new_entry = icalendar::Event::new();
            new_entry.uid(&format!("{}-{}", &view_entry.uid, &day)); // Repeat events
                                                                     // get the same uid,
                                                                     // but we don't know
                                                                     // about the repeats here
                                                                     // so every date is unique.
            let summary = name?;
            if filter_invites && summary.starts_with("Einladung: ") {
                anyhow::bail!("Not accepted");
            }
            new_entry.summary(&summary);
            if let Ok(start) = start {
                let end = end?;
                new_entry.starts::<icalendar::CalendarDateTime>(
                    chrono::DateTime::parse_from_str(&start, DATETIME_FORMAT)?
                        .with_timezone(&chrono::Utc)
                        .into(),
                );
                new_entry.ends::<icalendar::CalendarDateTime>(
                    chrono::DateTime::parse_from_str(&end, DATETIME_FORMAT)?
                        .with_timezone(&chrono::Utc)
                        .into(),
                );
            } else {
                // Seems to be all day

                new_entry.starts::<chrono::NaiveDate>(
                        chrono::DateTime::parse_from_str(&day, DATETIME_FORMAT)?
                        .with_timezone(&chrono::Utc)
                        .date_naive()
                        .into(),
                    );

            }

            if let Ok(location) = location {
                new_entry.location(&location);
            }

            Ok(new_entry.done())
        })();
        if let Ok(entry) = entry {
            calendar.push(entry);
        } else {
            tracing::warn!("Invalid ViewEntry: {:?}", entry);
        }
    }

    Ok(calendar)
}
